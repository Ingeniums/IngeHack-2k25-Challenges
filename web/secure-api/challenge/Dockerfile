FROM node:20

RUN apt update && apt install -y curl gnupg

RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

RUN chown -R appuser:appgroup /app

USER appuser

EXPOSE 3000

CMD ["node", "server.js"]
