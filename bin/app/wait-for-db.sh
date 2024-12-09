#!/bin/sh
set -e

echo "Waiting for PostgreSQL to be available..."
while ! nc -z $DB_HOSTNAME $DB_PORT; do
  echo "PostgreSQL not available yet..."
  sleep 1
done

echo "PostgreSQL is up"