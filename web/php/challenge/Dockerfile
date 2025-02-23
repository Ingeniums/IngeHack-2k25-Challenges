FROM node:20-alpine

WORKDIR /app

COPY src/package*.json ./
RUN npm install

COPY src/ ./

RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]