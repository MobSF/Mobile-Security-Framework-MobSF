script_path=$(dirname $0)
if [ "$script_path" != "scripts" ] && [ "$script_path" != "./scripts" ]; then
    echo 'Please run script from MobSF directory '
    echo './scripts/update_apkid.sh '
    exit  1
fi
current_dir=$(pwd)
rules_dir=${current_dir}/venv/lib/python3.6/site-packages/apkid/rules/
virtualenv venv -p python3
source venv/bin/activate
platform='unknown'
unamestr=`uname`
if [[ "$unamestr" == 'Darwin' ]]; then
  export ARCHFLAGS="-arch x86_64"
  export LDFLAGS="-L/usr/local/opt/openssl/lib"
  export CFLAGS="-I/usr/local/opt/openssl/include"
fi
git clone https://github.com/rednaga/APKiD.git 
cd APKiD 
python3 prep-release.py 
cp apkid/rules/rules.yarc ../venv/lib/python3.6/site-packages/apkid/rules/  
cd ..
if [[ "$unamestr" == 'Darwin' ]]; then
  sed -i ' ' "s#RULES_DIR =.*#RULES_DIR =  \"$rules_dir\"#" ./venv/lib/python3.6/site-packages/apkid/rules.py 
 else
  sed -i "s#RULES_DIR =.*#RULES_DIR =  \"$rules_dir\"#" ./venv/lib/python3.6/site-packages/apkid/rules.py
fi 
rm -fr APKiD
