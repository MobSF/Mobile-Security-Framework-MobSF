#!/bin/bash
var="$1"

function validate_ip () {
local IP=$1
local stat=1

if [[ $IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    OIFS=$IFS
    IFS='.'
    ip=($IP)
    IFS=$OIFS
    [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
        && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
    stat=$?
fi
if [ "$stat" -eq 0 ]; then
   return $stat
else
   echo 'Bad IP'
   exit 1   
fi
}

function validate_port () {
local PORT=$1
if [ -z "$PORT" ]; then
    echo 'Port can not be empty'
    exit 1
fi    
if [ "$PORT" -gt 1024 ] && [ "$PORT" -lt 65535 ]; then
    return 0
else
    echo 'Invalid Port'
    exit 1
fi    
}

if [ ! -z "$var" ]; then
    IP=$(echo $var | awk -F':' '{print $1}')
    PORT=$(echo $var | awk -F':' '{print $2}')
    validate_ip $IP
    validate_port $PORT
 else
    IP='[::]'
    PORT='8000'
fi	 
python3 -m poetry run gunicorn -b ${IP}:${PORT} mobsf.MobSF.wsgi:application --workers=1 --threads=10 --timeout=3600 \
    --log-level=citical --log-file=- --access-logfile=- --error-logfile=- --capture-output
