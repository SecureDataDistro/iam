import {JWT, VerifyingClient, SigningClient} from "@hub";
import { minimatch } from 'minimatch'

export interface JWTSigningRequest {
    entity: string
    claims: string[]
}

class URNError extends Error {
    constructor(message: string) {
      super(message);
      this.name = 'URNError';
    }
  }
export class GatewayURN {
    urn;
    constructor(val: string) {
        const elements = val.split(":");
        const elementLen = elements.length;
        switch(elementLen) {
            case 1: 
                this.urn = `sdd:hub:network:gateway:${val}`;
                break;
            case 5:
                this.urn = val;
                break;
            default:
                throw new URNError(`unknown number of elements (${elementLen}) in value ${val}`);
        }
    }
}

export class IamURN {
    urn;
    constructor(val: string) {
        const elements = val.split(":");
        const elementLen = elements.length;
        switch (elementLen) {
            case 5:
                if (!(elements[3] == "kms" || elements[3] == "local")) throw new URNError("IAM URN type must be kms or local")
                this.urn = val;
                break;
            case 2:
                if (!(elements[0] == "kms" || elements[0] == "local")) throw new URNError("IAM URN type must be kms or local")
                this.urn = `sdd:hub:iam:${elements[0]}:${elements[1]}`;
                break;
            default:
                throw new URNError(`unknown number of elements (${elementLen}) in value ${val}`);
        }        
    }
}

export class OrgURN {
    urn;
    constructor(val: string) {
        const elements = val.split(":");
        const elementLen = elements.length;

        switch(elementLen) {
            case 5:
                this.urn = val;
                break;
            case 2:
                this.urn = `dss:org:${elements[0]}:${elements[1]}:${elements[0]}`;
                break;
            default:
                throw new URNError(`unknown number of elements (${elementLen}) in value ${val}`);
        }
        
    }
}

export class DataRepoURN {
    urn;
    //constructor(orgUuid: string, repoName: string, entityName: string) {
    constructor(val: string){
        const elements = val.split(":");
        const elementLen = elements.length;

        switch(elementLen) {
            case 5:
                this.urn = val;
                break;
            case 2:
                let repo: string;
                let entity: string;
                switch (elements[1].split("/").length) {
                    case 1:
                        repo = elements[1];
                        entity = "*";
                        break;
                    case 2:
                        repo = elements[1].split("/")[0];
                        entity = elements[1].split("/")[1];
                        break;
                    default:
                        throw new URNError(`unknown data repo entity format ${val}`);
                }

                this.urn = `dss:org:${elements[0]}:repo:${repo}/${entity}`;
                break;
            default:
                throw new URNError(`unknown number of elements (${elementLen}) in value ${val}`);
        }
    }
}

export class UserURN {
    urn;
    constructor(val: string) {
        const elements = val.split(":");
        const elementLen = elements.length;

        switch(elementLen) {
            case 2:
                this.urn = `dss:org:${elements[0]}:user:${elements[1]}`;
                break;
            case 5:
                this.urn = val;
                break;
            default:
                throw new URNError(`unknown number of elements (${elementLen}) in value ${val}`);
        }
    }
}

export class GroupsUrn {
    urn;
    constructor(val: string) {
        const elements = val.split(":");
        const elementLen = elements.length;

        switch(elementLen) {
            case 2:
                this.urn = `dss:org:${elements[0]}:group:${elements[1]}`;
                break;
            case 5:
                this.urn = val;
                break;
            default:
                throw new URNError(`unknown number of elements (${elementLen}) in value ${val}`);
        }
    }
}

export class Authorizer {
    endpoint: string;
    verifier: VerifyingClient
    constructor(pubKeyEndpoint: string) {
        this.endpoint = pubKeyEndpoint;
        this.verifier = new VerifyingClient(this.endpoint);
    }
    

    async isVerified(token: string): Promise<JWT|undefined> {
        // verify the signature of the JWT
        return this.verifier.verify(token);
    }

    async isAuthorized(jwt: JWT, urns: string[]): Promise<boolean> {
        // every urn must have a match on one of the claims within the JWT
        let urnsAuthorized = [] as boolean[];

        urns.forEach(urn => {
            let claimAuthorized = false;
            jwt.claims.forEach(claim => {
                if (minimatch(urn, claim)) {
                    claimAuthorized = true;
                }
            });
            urnsAuthorized.push(true);
        });

        if (urnsAuthorized.length == urns.length) {
            return Promise.resolve(true);
        }

        return Promise.resolve(false);
    }
}

export class Signer {
    endpoint: string
    signingClient: SigningClient

    constructor(signingEndpoint: string) {
        this.endpoint = signingEndpoint;
        this.signingClient = new SigningClient(this.endpoint);
    } 

    async requestSigning(request: JWTSigningRequest): Promise<{token:string}> {
        return this.signingClient.sendRequest(request);
    }
}
