FROM node:20-slim
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --production --silent && npm cache clean --force
COPY index.js ./
EXPOSE 5000
USER node
CMD ["node", "index.js"]