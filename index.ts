import {Authorizer as authorizer, Signer as signer, DataRepoURN, UserURN} from "./src";
import { Command } from 'commander';
import chalk from "chalk";

export const Authorizer = authorizer;

export async function CLI(){
    const program = new Command();

    program
        .name("iam-cli")
        .description('cli tool for signing and verifying jwt tokens');

    program.command('sign')
        .description('use the jwt signing service to sign a jwt')
        .requiredOption('-e, --endpoint <http(s)://domain/token>', 'jwt signing service endpoint')
        .requiredOption('-u, --user <orgId>:<userId>', 'user entity for jwt')
        .requiredOption('-c, --claims <orgId:repoId>,<orgId:repoId>,...', 'comma-separate list of claims in format <OrgId>:<RepoId>')
        .action(async (opts) => {
            const endpoint = String(opts.endpoint);
            console.log(chalk.greenBright(`* using signing service at ${endpoint}`))
            const entity = new UserURN(String(opts.user));
            const claims = String(opts.claims).split(",").map(claim => {
                return new DataRepoURN(claim)
            });

            console.log(chalk.greenBright(`* signing jwt for user ${entity.urn} with claims:`));
            claims.forEach(claim => {console.log(chalk.greenBright(`* \t- ${claim.urn}`))});

            const client = new signer(endpoint);
            const jwtReq = {
                entity: entity.urn,
                claims: claims.map(claim => {
                    return claim.urn
                })
            }
            const jwtString = (await client.requestSigning(jwtReq))
            console.log(chalk.greenBright("* token: "), jwtString.token);
        })

    program.command('verify')
        .description('verify a jwt using the verify endpoint')
        .requiredOption('-e, --endpoint <http(s)://domain/pub>', 'jwt public key endpoint')
        .requiredOption('-t, --token <string>', 'jwt token to verify and validate')
        .option('-c, --claims <claim,claim,...>', 'comma-separated list of claims to validate')
        .action(async (opts) => {
            const endpoint = String(opts.endpoint);
            const token = String(opts.token);
            const auth = new authorizer(endpoint);

            const jwt = await auth.isVerified(token);

            if (jwt == undefined) {
                throw new Error("JWT is not verified")
            }

            console.log(jwt.sub, jwt.claims);

            if (opts.claims) {
                const claims = String(opts.claims).split(",").map(claim => {
                    return new DataRepoURN(claim);
                });

                console.log(`validating claims ${JSON.stringify(claims)}`);

                const authz = await auth.isAuthorized(jwt, claims.map(claim => {return claim.urn}));

                console.log(authz);
            }
        })

    program.parse(process.argv.slice(2));
};