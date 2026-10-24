#!/bin/bash
var="$1"

function validate_ip() {
    local IP=$1
    if [[ $IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        for i in ${IP//./ }; do
            ((i >= 0 && i <= 255)) || { echo 'Bad IP'; exit 1; }
        done
    else
        echo 'Bad IP'
        exit 1
    fi
}

function validate_port() {
    local PORT=$1
    if [[ -z "$PORT" || "$PORT" -le 1024 || "$PORT" -ge 65535 ]]; then
        echo 'Invalid Port'
        exit 1
    fi
}

if [[ -n "$var" ]]; then
    IP="${var%%:*}"
    PORT="${var##*:}"
    validate_ip "$IP"
    validate_port "$PORT"
else
    IP='[::]'
    PORT='8000'
fi

cleanup_android() {
    python3 -m poetry run python manage.py cleanup_android || true
}
trap cleanup_android EXIT

python3 -m poetry run gunicorn --config scripts/gunicorn_config.py -b ${IP}:${PORT} mobsf.MobSF.wsgi:application --workers=1 --threads=10 --timeout=3600 \
    --log-level=critical --log-file=- --access-logfile=- --error-logfile=- --capture-output
