#Readme for Windows-App-Analysis
##Why
Sadly [binskim](https://www.nuget.org/packages/Microsoft.CodeAnalysis.BinSkim/) is only available on windows. So even for static analysis, a windows VM is required.

##Caution
Use and separate Windows-VM for MobSF and *don't* expose it to a network range, where an attack might be coming from. The best solution is to set it to host-only mode.

##Steps on the Windows-VM
1. Install the following requirements on the VM
  * [Python 3](https://www.python.org/downloads/)
  * Flask (via `python -m pip install flask`)
2. Download the [setup.py](https://raw.githubusercontent.com/DominikSchlecht/Mobile-Security-Framework-MobSF/master/install/windows/setup.py) script and run it
3. If there are no errors, everything is good and the RPC-Server should be running

##Steps for MobSF
To integrate a Windows-VM into MobSF, please following these steps.
* Get the IP of you VM and set in the MobSF/settings.py-File under Windows-VM
* Done. It's that simple.
