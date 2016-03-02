import os
def FindVbox():
	vbox_path = ["/usr/bin/VBoxManage", "/usr/local/bin/VBoxManage"]
	for path in vbox_path:
		if os.path.isfile(path):
			return path
	print "\n[WARNING] Could not find VirtualBox path." 
	return vbox_path[0]