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
	jadx_archive=$(curl -s https://api.github.com/repos/skylot/jadx/releases/latest | grep '.browser_download_url' | grep -v 'jadx-gui' |awk  -F'"' '{print $4}') 
	base=$(basename $jadx_archive)
	curl -L -f --output /tmp/${base} ${jadx_archive}
	if [ "$?" -gt "0" ]; then
            echo 'Download Failed'
	    exit 1
	fi    
	echo 'Installing Jadx in tools directory'
	mkdir -p ./StaticAnalyzer/tools/jadx
	unzip -o /tmp/${base} -d ./StaticAnalyzer/tools/jadx
	unamestr=$(uname)
        if [[ "$unamestr" == 'Darwin' ]]; then
           sed -i '' "s#DEFAULT_JVM_OPTS=.*#DEFAULT_JVM_OPTS='\"-Xms128M\" \"-Xmx4g\" \"-XX:+UseG1GC\" \"-Dlogback.configurationFile=${PWD}/jadx.xml\"'#" ./StaticAnalyzer/tools/jadx/bin/jadx
        else   
           sed -i "s#DEFAULT_JVM_OPTS=.*#DEFAULT_JVM_OPTS='\"-Xms128M\" \"-Xmx4g\" \"-XX:+UseG1GC\" \"-Dlogback.configurationFile=${PWD}/jadx.xml\"'#" ./StaticAnalyzer/tools/jadx/bin/jadx
	fi
	rm -f /tmp/${base}
	echo 'Done'
fi
