echo 
echo "=======================MobSF Clean Script======================="
echo "Running this script will delete the Scan database, all files uploaded and generated."
read -p "Are you sure? " -n 1 -r
echo 
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo "Deleting all PYC"
	find . -name "*.pyc" -exec rm -rf {} \;
	echo "Deleting all .DS_Store"
	find . -name ".DS_Store" -exec rm -rf {} \;
	echo "Deleting all Uploads"
	rm -rf uploads/*
	echo "Deleting all Downloads"
	rm -rf static/downloads/*
	echo "Deleting Screen Cache"
	rm -rf static/screen/screen.png
	echo "Deleting temp and log files"
	rm -rf logs/*
	rm -rf classes-error.zip
	echo "Deleting DB"
	rm -rf db.sqlite3
	echo "Migrating DB changes"
	python manage.py migrate
	echo "Deleting App Secret File"
	rm -rf MobSF/secret
	echo "Creating certs directory"
	mkdir logs/certs
	echo "Creating Placeholders"
	echo > logs/certs/PLACEHOLDER
	echo > uploads/PLACEHOLDER
	echo > static/downloads/PLACEHOLDER
fi