adb shell procrank ^| grep com.earn.rewards.rewardometer ^| awk '{ print $1 }' ^| xargs strace -c -q -p >Results\\syscalls51299266ECBC1B26D8CED685BB1FEA2E0D1478.txt
