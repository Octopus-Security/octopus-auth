FROM node:22-alpine

RUN apk upgrade --no-cache

WORKDIR /app

COPY package*.json ./
RUN npm install --only=production

COPY . .

RUN mkdir -p /app/data

EXPOSE 3002

CMD ["node", "index.js"]
