FROM node:26-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build

FROM node:26-alpine
WORKDIR /app
ENV NODE_ENV=production LATCHKEY_CONFIG=/config/latchkey.yaml
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --from=build /app/dist ./dist
RUN mkdir -p /data && chown node:node /data && ln -s /app/dist/cli.js /usr/local/bin/latchkey && chmod +x /app/dist/cli.js
USER node
VOLUME /data
CMD ["node", "dist/cli.js", "serve"]
