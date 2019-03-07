script_path=$(dirname $0)
if [ "$script_path" != "scripts" ] && [ "$script_path" != "./scripts" ]; then
    echo 'Please run script from MobSF directory '
    echo './scripts/update_apkid.sh '
    exit  1
fi
current_dir=$(pwd)
rules_dir=${current_dir}/root/Mobile-Security-Framework-MobSF/MalwareAnalyzer/
virtualenv venv -p python3
source venv/bin/activate
platform='unknown'
unamestr=`uname`
git clone https://github.com/rednaga/APKiD.git 
cd APKiD 
python3 prep-release.py 
cp apkid/rules/rules.yarc ${rules_dir}  
cd ..
if [[ "$unamestr" == 'Darwin' ]]; then
  sed -i ' ' "s#RULES_DIR =.*#RULES_DIR =  \"$rules_dir\"#" ./venv/lib/python3.6/site-packages/apkid/rules.py 
 else
  sed -i "s#RULES_DIR =.*#RULES_DIR =  \"$rules_dir\"#" ./venv/lib/python3.6/site-packages/apkid/rules.py
fi 
rm -fr APKiD
