#!/bin/bash

echo 
echo '=======================MobSF Clean Script for Unix======================='
echo 'Running this script will delete the scan database, all files uploaded and generated.'

script_path=$(basename "$(dirname "$0")")
mobsf_home="$HOME/.MobSF"

# Ensure the script is run from the correct directory
if [[ "$script_path" != "scripts" ]]; then
    echo 'Please run this script from the MobSF directory:'
    echo './scripts/clean.sh'
    exit 1
fi

# Confirmation prompt
VAL=${1:-}
if [[ -z "$VAL" ]]; then
    read -p 'Continue? (Y/N): ' confirm
    [[ $confirm =~ ^[yY]([eE][sS])?$ ]] || exit 1
    VAL=$confirm
fi

echo
if [[ "$VAL" =~ ^[yY]$ ]]; then
    echo 'Cleaning up MobSF directories and files...'

    # Remove files from key directories
    rm -rf ./mobsf/{uploads,downloads,StaticAnalyzer/migrations,DynamicAnalyzer/migrations,MobSF/migrations}/*
    
    echo 'Removing Python bytecode and cache files'
    find ./ -type f -name "*.pyc" -o -name "*.pyo" -delete
    find ./ -type d -name "__pycache__" -exec rm -rf {} +

    # Remove temporary, log, and database files
    echo 'Deleting temporary, log, and database files'
    rm -f ./mobsf/debug.log ./classes* ./mobsf/db.sqlite3 ./mobsf/secret

    # Remove the MobSF data directory if it exists
    if [[ -d "$mobsf_home" ]]; then
        echo "Deleting MobSF data directory: $mobsf_home"
        rm -rf "$mobsf_home"
    fi

    echo 'Cleanup complete.'
fi
