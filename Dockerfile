# InjectScan MCP server (stdio). Starts with no key.
#   docker build -t injectscan-mcp . && docker run -i --rm injectscan-mcp
FROM node:20-slim
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src ./src
USER node
CMD ["node", "src/mcp-stdio.js"]
