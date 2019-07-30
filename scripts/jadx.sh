#!/bin/bash
echo 
echo '=======================MobSF Jadx Install======================='
echo 'Running this script will install Jadx.'

script_path=$(dirname $0)
if [ "$script_path" != "scripts" ] && [ "$script_path" != "./scripts" ]; then
    echo 'Please run script from MobSF directory '
    echo './scripts/jadx.sh '
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
	echo 'Downloading Jadx'
	curl -L --output /tmp/jadx.zip  https://github.com/skylot/jadx/releases/download/v1.0.0/jadx-1.0.0.zip
	echo 'Installing JAdix in tools directory'
	mkdir -p ./StaticAnalyzer/tools/jadx
	unamestr=$(uname)
        if [[ "$unamestr" == 'Darwin' ]]; then
           sed -i '' "s#DEFAULT_JVM_OPTS=.*#DEFAULT_JVM_OPTS='\"-Xms128M\" \"-Xmx4g\" \"-XX:+UseG1GC\" \"-Dlogback.configurationFile=${PWD}/jadx.xml\"'#" ./StaticAnalyzer/tools/jadx/bin/jadx
        else   
           sed -i "s#DEFAULT_JVM_OPTS=.*#DEFAULT_JVM_OPTS='\"-Xms128M\" \"-Xmx4g\" \"-XX:+UseG1GC\" \"-Dlogback.configurationFile=${PWD}/jadx.xml\"'#" ./StaticAnalyzer/tools/jadx/bin/jadx
	fi
        unzip -o /tmp/jadx.zip -d ./StaticAnalyzer/tools/jadx/
	rm -f /tmp/jadx.zip
	echo 'Done'
fi
