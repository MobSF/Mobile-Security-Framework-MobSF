#!/bin/bash
set -e

# wait for the database to be ready and migrations to be applied
echo "Waiting for the database to be ready..."
sleep 10

echo "Starting Django Q Cluster..."
exec python3 manage.py qcluster
