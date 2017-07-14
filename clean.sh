echo 
echo "=======================MobSF Clean Script for Unix======================="
echo "Running this script will delete the Scan database, all files uploaded and generated."
read -p "Are you sure? " -n 1 -r
echo 
if [[ $REPLY =~ ^[Yy]$ ]]
then
	echo "Deleting all Uploads"
	rm -rf uploads/*
	echo "Deleting all Downloads"
	rm -rf downloads/*
	echo "Deleting Static Analyzer Migrations"
	rm -rf StaticAnalyzer/migrations/*
	echo "Deleting python byte code files"
        find . -name "*.pyc" -exec rm -rf {} \;
        echo "Deleting temp and log files"
	rm -rf logs/*
	rm -rf classes-error.zip
	echo "Deleting DB"
	rm -rf db.sqlite3
	echo "Deleting Secret File"
	rm -rf secret
	echo "Done"
fi
