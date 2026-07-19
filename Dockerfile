FROM node:22.19-alpine

# Install curl for health checks
RUN apk add --no-cache curl

WORKDIR /app

COPY --chown=node:node package*.json ./
RUN npm ci

COPY --chown=node:node . .
RUN npm run build && npm prune --omit=dev

ENV NODE_ENV=production
EXPOSE 3001

USER node

CMD ["node", "dist/server.js"]
