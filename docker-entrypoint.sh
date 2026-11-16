#!/bin/sh
set -e
python app.py init-db
exec gunicorn -c gunicorn.conf.py app:app
