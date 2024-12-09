#!/bin/sh

sh bin/app/wait-for-db.sh

if [[ "$1" == "--dev" ]]; then
  echo "Running in development mode"
  python3 manage.py runserver 0.0.0.0:8000
else
  echo "Running in production mode"
  gunicorn --bind 0.0.0.0:8000 app_settings.wsgi:application
fi