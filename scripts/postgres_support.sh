#!/bin/bash
set -e
POSTGRES=$1
echo "Postgres support : ${POSTGRES}"
if [ "$POSTGRES" == True ]; then
    pip3 install psycopg2-binary
    #Enable postgres support
    sed -i '/# Sqlite3 support/,/# End Sqlite3 support/d' mobsf/MobSF/settings.py && \
    sed -i '/# Postgres DB - Install psycopg2/,/"""/d' mobsf/MobSF/settings.py && \
    sed -i '/# End Postgres support/,/"""/d' mobsf/MobSF/settings.py
fi
