# FROM python:slim AS app
# RUN pip install --no-cache-dir flask==3.1.0 torch==2.5.1


# FROM pwn.red/jail
# COPY --from=app / /srv
# COPY app.py /srv/app/run
# COPY flag.txt /srv/app/flag.txt

FROM python:3.12

WORKDIR /app

RUN pip install --no-cache-dir flask==3.1.0 torch==2.5.1

# Copy the rest of the application files
COPY . .

# create an unprivileged user that runs the app and can only read the flag which is owned by the admin
RUN useradd -m app
RUN chown -R app:app /app
RUN chmod 400 /app/flag.txt

USER app

# Expose the port Flask runs on
EXPOSE 8080

# Command to run the application
CMD ["python", "app.py"]


# to test later
