FROM docker.io/library/node:18-bookworm AS builder

COPY --chown=node:node ./ /app

WORKDIR /app

RUN yarn install

RUN yarn build

####################

FROM docker.io/library/node:18-alpine

RUN npm i -g run-func

WORKDIR /app

COPY --chown=node:node  --from=builder /app/dist/index.js ./index.js


ENTRYPOINT [ "npx", "run-func", "./index.js" ]

CMD [ "CLI" ]