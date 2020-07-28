#!/bin/bash
set -e
POSTGRES=$1
echo "Postgres support : ${POSTGRES}"
if [ "$POSTGRES" == True ]; then
 pip3 install psycopg2-binary
 #Enable postgres support
 sed -i '/# Sqlite3 suport/,/# End Sqlite3 support/d' ../MobSF/settings.py && \
 sed -i '/# Postgres DB - Install psycopg2/,/"""/d' ../MobSF/settings.py && \
 sed -i '/# End Postgres support/,/"""/d' ../MobSF/settings.py && \
# sed -i "s/'USER': '',/'postgres': '$POSTGRES_USER',/" ../MobSF/settings.py && \
# sed -i "s/'PASSWORD': '',/'PASSWORD': '$POSTGRES_PASSWORD',/" ../MobSF/settings.py && \
# sed -i "s/'NAME': '',/'mobsf': '$POSTGRES_DB',/" ../MobSF/settings.py && \
# sed -i "s/'HOST': 'localhost',/'HOST': '$POSTGRES_HOST',/" ../MobSF/settings.py
 cat ../MobSF/settings.py
fi