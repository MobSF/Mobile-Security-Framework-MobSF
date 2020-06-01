#!/bin/bash
# Dev Server
#. venv/bin/activate && python manage.py runserver
# Prod Server
var="$1"
if [ ! -z "$var" ]; then
    IP=$(echo $var | awk -F':' '{print $1}')
    if echo "$IP" | { IFS=. read a b c d e;
    test "$a" -ge 0 && test "$a" -le 255 &&
    test "$b" -ge 0 && test "$b" -le 255 &&
    test "$c" -ge 0 && test "$c" -le 255 &&
    test "$d" -ge 0 && test "$d" -le 255 &&
    test -z "$e"; }; then
        PORT=$(echo $var | awk -F':' '{print $2}')
       else
       	echo 'Bad IP !'
        exit 1	
    fi 	
 else
    IP='0.0.0.0'
    PORT='8000'
fi	 
. venv/bin/activate && gunicorn -b ${IP}:${PORT} MobSF.wsgi:application --workers=1 --threads=10 --timeout=1800
