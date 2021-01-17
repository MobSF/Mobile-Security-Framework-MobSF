#!/bin/bash
echo 
echo '=======================MobSF Clean Script for Unix======================='
echo 'Running this script will delete the Scan database, all files uploaded and generated.'

script_path=$(dirname $0)
if [ "$script_path" != "scripts" ] && [ "$script_path" != "./scripts" ]; then
    echo 'Please run script from mobsf.MobSF directory '
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
	rm -rf ./mobsf/uploads/*
	echo 'Deleting all Downloads'
	rm -rf ./mobsf/downloads/*
	echo 'Deleting Static Analyzer Migrations'
	rm -rf ./mobsf/StaticAnalyzer/migrations/*
	echo 'Deleting Dynamic Analyzer Migrations'
	rm -rf ./mobsf/DynamicAnalyzer/migrations/*
	echo 'Deleting MobSF Migrations'
	rm -rf ./mobsf/MobSF/migrations/*
	echo 'Deleting python byte code files'
        find ./ -name "*.pyc" -exec rm -rf {} \;
        find ./ | grep -E "(__pycache__|\.pyo$)" | xargs rm -rf
        echo 'Deleting temp and log files'
	rm -rf ./mobsf/debug.log
	rm -rf ./classes*
	echo 'Deleting DB'
	rm -rf ./mobsf/db.sqlite3
	echo 'Deleting Secret File'
	rm -rf ./mobsf/secret
	echo 'Done'
fi
