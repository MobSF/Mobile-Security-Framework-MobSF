This directory contains the binaries to install and use IPFW and
DUMMYNET on a Windows Machine. The kernel part is an NDIS module,
whereas the user interface is a command line program.

1. INSTALL THE NDIS DRIVER

- open the configuration panel for the network card in use
  (either right click on the icon on the SYSTRAY, or go to
  Control Panel -> Network and select one card)

- click on Properties->Install->Service->Add
- click on 'Driver Disk' and select 'netipfw.inf' in this folder
- select 'ipfw+dummynet' which is the only service you should see
- click accept on the warnings for the installation of an unknown
  driver (roughly twice per existing network card)

Now you are ready to use the emulator. To configure it, open a 'cmd'
window and you can use the ipfw command from the command line.
Otherwise click on the 'TESTME.bat' which is a batch program that
runs various tests.

2. UNINSTALL THE DRIVER

- select a network card as above.
- click on Properties
- select 'ipfw+dummynet'
- click on 'Remove'
