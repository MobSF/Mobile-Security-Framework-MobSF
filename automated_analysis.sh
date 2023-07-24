#!/bin/bash
# Change the values accordingly based on system 
python3 /home/dylan/Desktop/MobSF_Scripts/start_vm.py &
sleep 20
echo "Please enter filename with its extension: "
read filename
echo "Please enter the password for the file if any"
read password
hash=$(python3 /home/dylan/Desktop/MobSF_Scripts/main.py  "$filename" "$password")
# Copies out analysis files from default save locations
cp -r /home/dylan/.MobSF/uploads/$hash /home/dylan/Desktop/MobSF_reports/$hash
mv /home/dylan/Desktop/MobSF_reports/$hash/$hash /home/dylan/Desktop/MobSF_reports/$hash/Analysis_files
cp /home/dylan/.MobSF/downloads/$hash-web_traffic.txt /home/dylan/Desktop/MobSF_reports/$hash/Analysis_files
gnome-terminal -- pkill -f qemu-system-x86_64
echo "Process stopped"
exit
