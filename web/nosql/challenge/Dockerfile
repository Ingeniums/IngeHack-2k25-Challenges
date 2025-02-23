FROM python:3.10

ENV POSTGRES_USER=ctfuser
ENV POSTGRES_PASSWORD=ctfpass
ENV POSTGRES_DB=ctfdb

RUN apt-get update && apt-get install -y \
    postgresql postgresql-contrib \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/lib/postgresql/data && chown -R postgres:postgres /var/lib/postgresql

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x start.sh

EXPOSE 8000

CMD ["./start.sh"]
