FROM node:24-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY src ./src
RUN mkdir -p /app/data && chown -R node:node /app
USER node
ENV HOST=0.0.0.0 PORT=8787 DATA_PATH=/app/data/gatekeeper.sqlite
EXPOSE 8787
CMD ["node", "src/main.js"]
