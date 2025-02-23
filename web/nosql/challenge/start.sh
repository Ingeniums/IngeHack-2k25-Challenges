#!/bin/bash

echo "Starting PostgreSQL service..."
service postgresql start

echo "host all all 127.0.0.1/32 trust" >> /etc/postgresql/15/main/pg_hba.conf
echo "listen_addresses='*'" >> /etc/postgresql/15/main/postgresql.conf

service postgresql restart

echo "Waiting for PostgreSQL to start..."
until pg_isready -U ctfuser -h 127.0.0.1 -p 5432; do
    echo "PostgreSQL is not ready yet. Retrying in 5 seconds..."
    sleep 5
done
echo "PostgreSQL is ready!"

su - postgres -c "psql -c \"CREATE USER ctfuser WITH PASSWORD 'ctfpass';\"" || echo "User already exists."
su - postgres -c "psql -c \"CREATE DATABASE ctfdb OWNER ctfuser;\"" || echo "Database already exists."
su - postgres -c "psql -c \"ALTER USER ctfuser CREATEDB;\""

function wait_for_db() {
    echo "Waiting for Django database connection..."
    until python manage.py shell -c "
import sys
from django.db import connections
from django.db.utils import OperationalError

conn = connections['default']
try:
    conn.cursor()
    sys.exit(0)
except OperationalError:
    sys.exit(1)
"; do
        echo "Database is not ready yet. Retrying in 5 seconds..."
        sleep 5
    done
    echo "Database is ready!"
}

wait_for_db  

echo "Applying migrations..."
python manage.py makemigrations
python manage.py migrate

echo "Collecting static files..."
python manage.py collectstatic --noinput

if python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
exit(0) if User.objects.filter(is_superuser=True).exists() else exit(1)
"; then
    echo "Superuser already exists. Skipping creation."
else
    echo "Creating superuser..."
    python manage.py createsuperuser --noinput --username "admin" --email "admin@domain.com"
    python manage.py shell -c "
from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
User = get_user_model()
user = User.objects.get(username='admin')
user.password = make_password('palestine4ever')
user.save()
"
fi

if python manage.py shell -c "
from quotes.models import Quote
from django.contrib.auth import get_user_model
User = get_user_model()
admin_user = User.objects.get(username='admin')
exit(0) if Quote.objects.filter(author=admin_user).count() > 0 else exit(1)
"; then
    echo "Quotes already exist. Skipping creation."
else
    echo "Creating quotes..."
    python manage.py shell -c "
from quotes.models import Quote
from django.contrib.auth import get_user_model
User = get_user_model()
admin_user = User.objects.get(username='admin')
Quote.objects.create(author=admin_user, text='ingehack{us3_0rm_w1th_cauti0n_t0_avoid_injecti0ns}', private=True)
Quote.objects.create(author=admin_user, text='This is a public quote.', private=False)
"
fi

echo "Setup complete!"

echo "Starting Django server..."
exec python manage.py runserver 0.0.0.0:8000
