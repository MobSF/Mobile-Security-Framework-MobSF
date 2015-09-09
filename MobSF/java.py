import subprocess,platform,re,os
#Maintain JDK Version
JAVA_VER='1.7|1.8|1.9|2.0|2.1|2.2|2.3'
def FindJava():
	try:
		if platform.system()=="Windows":
			print "\n[INFO] Finding JDK Location in Windows...."
			WIN_JAVA_BASE="C:/Program Files/Java/" #JDK 7 jdk1.7.0_17/bin/
			JDK=[]
			for dirname in os.listdir(WIN_JAVA_BASE):
				if "jdk" in dirname:
					JDK.append(dirname)
			if len(JDK)==0:
				print "\n[ERROR] Oracle Java (JDK >=1.7) is not found!"
				return ""
			elif len(JDK)==1:
				print "\n[INFO] Oracle JDK Identified. Looking for JDK 1.7 or above"
				j=''.join(JDK)
				if re.findall(JAVA_VER,j):
					WIN_JAVA=WIN_JAVA_BASE+j+"/bin/"
					args=[WIN_JAVA+"java"]
					dat=RunProcess(args)
					if "oracle" in dat:
						print "\n[INFO] Oracle Java (JDK >= 1.7) is installed!"
						return WIN_JAVA
					else:
						print "\n[ERROR] Oracle JDK 1.7 or above is not found!"
						return ""
				else:
					print "\n[ERROR] Oracle JDK 1.7 or above is not found!"
					return ""
			elif len(JDK)>1:
				print "\n[INFO] Multiple JDK Instances Identified. Looking for JDK 1.7 or above"
				for j in JDK:
					if re.findall(JAVA_VER,j):
						WIN_JAVA=WIN_JAVA_BASE+j+"/bin/"
						break
					else:
						WIN_JAVA=""
				if len(WIN_JAVA)>1:
					args=[WIN_JAVA+"java"]
					dat=RunProcess(args)
					if "oracle" in dat:
						print "\n[INFO] Oracle Java (JDK >= 1.7) is installed!"
						return WIN_JAVA
					else:
						print "\n[ERROR] Oracle JDK 1.7 or above is not found!"
						return ""
				else:
					print "\n[ERROR] Oracle JDK 1.7 or above is not found!"
					return ""
			else:
				print "\n[ERROR] Oracle JDK 1.7 or above is not found!" 
				return ""
		else:
			print "\n[INFO] Finding JDK Location in Linux/MAC...."
			MAC_LINUX_JAVA="/usr/bin/"
			args=[MAC_LINUX_JAVA+"java"]
			dat=RunProcess(args)
			if "oracle" in dat:
				print "\n[INFO] Oracle Java is installed!"
				args=[MAC_LINUX_JAVA+"java", '-version']
				dat=RunProcess(args)
				f_line=dat.split("\n")[0]
				if  re.findall(JAVA_VER,f_line):
					print "\n[INFO] JDK 1.7 or above is available"
					return MAC_LINUX_JAVA
				else:
					print "\n[ERROR] Please install Oracle JDK 1.7 or above"
					return ""
			else:
				print "\n[ERROR] Oracle Java JDK 1.7 or above is not found!"
				return ""
	except Exception as e:
		print "\n[ERROR] Oracle Java (JDK >=1.7) is not found! Error - "+str(e)
		return ""
def RunProcess(args):
	try:
		proc = subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,)
		dat=''
		while True:
			line = proc.stdout.readline()
			if not line:
				break
			dat+=line
		return dat
	except Exception as e:
		print "\n[ERROR] Cannot Run Process - "+str(e)
		return ""