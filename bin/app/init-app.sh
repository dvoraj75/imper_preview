#!/bin/sh

sh bin/app/wait-for-db.sh

python3 manage.py init_app
