#!/usr/bin/env python
import os
import sys



if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "MobSF.settings")
    from django.core.management import execute_from_command_line
#----- Test
    execute_from_command_line(sys.argv)
