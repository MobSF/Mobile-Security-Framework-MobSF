#!/bin/bash
echo 
echo '=======================MobSF Clean Script for Unix======================='
echo 'Running this script will delete the Scan database, all files uploaded and generated.'

script_path=$(dirname $0)
if [ "$script_path" != "scripts" ] && [ "$script_path" != "./scripts" ]; then
    echo 'Please run script from MobSF directory '
    echo './scripts/clean.sh '
    exit  1
fi

if [ "$1" != "" ]; then
    VAL="$1"
else
    read -p 'Continue? (Y/N): ' confirm && [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]] || exit 1
    VAL=$confirm
fi
echo 
if [[ $VAL =~ ^[Yy]$ ]]
then
	echo 'Deleting all Uploads'
	rm -rf ./uploads/*
	echo 'Deleting all Downloads'
	rm -rf ./downloads/*
	echo 'Deleting Static Analyzer Migrations'
	rm -rf ./StaticAnalyzer/migrations/*
	echo 'Deleting Dynamic Analyzer Migrations'
	rm -rf ./DynamicAnalyzer/migrations/*
	echo 'Deleting MobSF Migrations'
	rm -rf ./MobSF/migrations/*
	echo 'Deleting python byte code files'
        find ./ -name "*.pyc" -exec rm -rf {} \;
        find ./ | grep -E "(__pycache__|\.pyo$)" | xargs rm -rf
        echo 'Deleting temp and log files'
	rm -rf ./logs/*
	rm -rf ./classes*
	echo 'Deleting DB'
	rm -rf ./db.sqlite3
	echo 'Deleting Secret File'
	rm -rf ./secret
	echo 'Done'
fi
