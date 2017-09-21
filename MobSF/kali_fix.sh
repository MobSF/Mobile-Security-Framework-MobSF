echo "Running Kali Fix to enable 32bit execution support"
export DEBIAN_FRONTEND=noninteractive
dpkg --add-architecture i386
apt-get update -q
apt-get install -q -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" libstdc++6:i386 zlib1g:i386 libncurses5:i386