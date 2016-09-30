#Readme for Windows-App-Analysis
##Why
Sadly [binskim](https://www.nuget.org/packages/Microsoft.CodeAnalysis.BinSkim/) is only available on windows. So even for static analysis, a windows VM is required.

##Caution
Use and separate Windows-VM for MobSF and *don't* expose it to a network range where an attack might be coming from. The best solution is to set it to host-only mode.

##Steps on the Windows-VM
1. Install the following requirements on the VM
  * [Python 3](https://www.python.org/downloads/)
  * rsa (via `python -m pip install rsa`)
2. Download the [setup.py](https://raw.githubusercontent.com/DominikSchlecht/Mobile-Security-Framework-MobSF/master/install/windows/setup.py) script and run it
3. There is some manual interaction, but if there are no errors, everything is good and the RPC-Server should be running
4. Do the steps of the next section for MobSF

##Steps for MobSF
To integrate a Windows-VM into MobSF, please following these steps.
* Get the IP of you VM and set in the MobSF/settings.py-File (search for `WINDOWS_VM_IP`)
* (If not yet done:) Copy the private rsa key from the vm to MobSF
