echo Migrating Database
poetry run python manage.py makemigrations
poetry run python manage.py makemigrations StaticAnalyzer
poetry run python manage.py migrate