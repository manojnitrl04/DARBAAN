FROM python:3.11.3-slim-buster
LABEL maintainer: "Madtin.com"
ENV PYTHONUNBUFFERED 1

WORKDIR /app
EXPOSE 8000

COPY requirements.txt requirements.txt

RUN apt-get update && \
    apt-get install -y libpq-dev gcc && \
    python -m pip install -r requirements.txt && \
    adduser --disabled-password --no-create-home appuser

USER appuser

COPY . .

#to run locally and coonec to localhost:8000
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]

