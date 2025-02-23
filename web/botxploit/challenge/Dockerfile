FROM mcr.microsoft.com/playwright/python:v1.48.0-focal
ENV FLASK_ENV=production \
    FLASK_DEBUG=0 \
    PYTHONUNBUFFERED=1

RUN groupadd -r appgroup && useradd -r -g appgroup appuser
WORKDIR /app
COPY requirements.txt requirements.txt
RUN pip install -r requirements.txt
COPY . .
RUN chown -R appuser:appgroup /app
USER appuser
EXPOSE 5000
ENV FLASK_APP=app.py
CMD ["flask", "run", "--host=0.0.0.0", "--port=5000"]