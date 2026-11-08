FROM docker.io/library/node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY web/kernel/asyncify.js web/kernel/image.js ./web/kernel/
COPY containers/compiler/server.mjs ./containers/compiler/server.mjs
USER node
EXPOSE 8080
CMD ["node", "containers/compiler/server.mjs"]
