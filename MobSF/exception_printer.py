import sys,linecache,os,time,datetime
from django.conf import settings

class Color(object):
	GREEN = '\033[92m'
	ORANGE = '\033[33m'
	RED = '\033[91m'
	BOLD = '\033[1m'
	END = '\033[0m'


def PrintException(msg,web=False):
	LOGPATH=settings.LOG_DIR
	if not os.path.exists(LOGPATH):
		os.makedirs(LOGPATH)
	exc_type, exc_obj, tb = sys.exc_info()
	f = tb.tb_frame
	lineno = tb.tb_lineno
	filename = f.f_code.co_filename
	linecache.checkcache(filename)
	line = linecache.getline(filename, lineno, f.f_globals)
	ts = time.time()
	st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
	dat= '\n['+st+']\n'+msg+' ({}, LINE {} "{}"): {}'.format(filename, lineno, line.strip(), exc_obj)
	if web:
		print Color.BOLD + Color.ORANGE + dat + Color.END
	else:
		print Color.BOLD + Color.RED + dat + Color.END
	with open(LOGPATH + 'MobSF.log','a') as f:
		f.write(dat)