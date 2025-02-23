FROM node:20

RUN useradd --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY package*.json ./

RUN npm i

COPY . ./

RUN chown -R appuser:appuser /app && chmod -R 555 /app

USER appuser

EXPOSE 3000

CMD ["node", "src/server.js"]
