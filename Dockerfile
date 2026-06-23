FROM node:22-alpine

RUN apk upgrade --no-cache

WORKDIR /app

ARG NPM_TOKEN
COPY package*.json ./
RUN echo "@octopus-security:registry=https://npm.pkg.github.com" > .npmrc \
 && echo "//npm.pkg.github.com/:_authToken=${NPM_TOKEN}" >> .npmrc \
 && npm install --only=production \
 && rm -f .npmrc

COPY . .

RUN mkdir -p /app/data

EXPOSE 3002

CMD ["node", "index.js"]
