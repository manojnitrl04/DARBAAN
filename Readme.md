To create virtual env:
        python -m venv d:\project\venv
Activate venv:
    d:\project\venv\Scripts/activate.bat   (In Linux,$ source ...path/activate.sh)
Check env usage:
    pip -V
Install dependencies:
    python -m pip install -r requirements.txt
List dependencies (post dev only).
    pip --freeze > requirements.txt


Running Locally:
python manage.py runserver 0.0.0.0:8080

Process:
For individual container:
    Build docker container:
        docker build -t darbaan_image .
        docker run -p 8000:8000 --name=container_darbaan darbaan_image

For multiple containers:
    Build docker compose

Locally 'docker-compose up' creates port forwarding, but docker-compose build does not!!!

Upload to registry:

Add to ECS Farget:

DB is in AWS RDS Postgres.
