#!/bin/bash
set -e
POSTGRES=$1
echo "Postgres support : ${POSTGRES}"
if [ "$POSTGRES" == True ]; then
 pip3 install psycopg2-binary
 #Enable postgres support
 sed -i '/# Sqlite3 suport/,/# End Sqlite3 support/d' ../MobSF/settings.py && \  
 sed -i ':a;N;$!ba;s/# Postgres DB - Install psycopg2\n"""/# Postgres DB - Install psycopg2/g' ../MobSF/settings.py && \  
 sed -i ':a;N;$!ba;s/# End Postgres support\n"""/# End Postgres support/g' ../MobSF/settings.py && \
 sed -i "s/'PASSWORD': '',/'PASSWORD': 'password',/" ../MobSF/settings.py && \
 sed -i "s/'HOST': 'localhost',/'HOST': 'postgres',/" ../MobSF/settings.py
fi
