echo Migrating Database
set venv=.\venv\Scripts\python
%venv% manage.py makemigrations
%venv% manage.py makemigrations StaticAnalyzer
%venv% manage.py migrate