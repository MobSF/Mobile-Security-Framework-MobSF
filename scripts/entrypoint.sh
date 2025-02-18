#!/bin/bash
set -e 

python3 manage.py makemigrations && \
python3 manage.py makemigrations StaticAnalyzer && \
python3 manage.py migrate
set +e
python3 manage.py createsuperuser --noinput --email ""
set -e
python3 manage.py create_roles

if [[ -n "${MOBSF_ASYNC_ALL_IN_ONE}" ]] && [[ "${MOBSF_ASYNC_ALL_IN_ONE}" -eq "1" ]] ; then
  # execute MobSF frontend and async worker queue in parallel
  commands=(
    'gunicorn -b 0.0.0.0:8000 "mobsf.MobSF.wsgi:application" --workers=1 --threads=10 --timeout=3600  --worker-tmp-dir=/dev/shm --log-level=citical --log-file=- --access-logfile=- --error-logfile=- --capture-output'
    'python3 manage.py qcluster'
  )
  exec /usr/bin/printf "%s\0" "${commands[@]}" | /usr/bin/xargs -0 -I {} -P "${#commands[@]}" /usr/bin/sh -c "{}"
else
  exec gunicorn -b 0.0.0.0:8000 "mobsf.MobSF.wsgi:application" --workers=1 --threads=10 --timeout=3600 \
      --worker-tmp-dir=/dev/shm --log-level=citical --log-file=- --access-logfile=- --error-logfile=- --capture-output
fi
