#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This file is part of Androwarn.
#
# Copyright (C) 2012, Thomas Debize <tdebize at mail.com>
# All rights reserved.
#
# Androwarn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Androwarn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Androwarn.  If not, see <http://www.gnu.org/licenses/>.

# This file maps the integer values with the constant names for several android classes

MediaRecorder_AudioSource = {
								0x0: 'DEFAULT',
								0x1: 'MIC',
								0x2: 'VOICE_UPLINK',
								0x3: 'VOICE_DOWNLINK',
								0x4: 'VOICE_CALL',
								0x5: 'CAMCORDER',
								0x6: 'VOICE_RECOGNITION',
								0x7: 'VOICE_COMMUNICATION'
							}

MediaRecorder_VideoSource = {
								0x0: 'DEFAULT',
								0x1: 'CAMERA'
							}

PackageManager_PackageInfo = {
								0x1: 	'GET_ACTIVITIES',
								0x4000:	'GET_CONFIGURATIONS',
								0x200:	'GET_DISABLED_COMPONENTS',
								0x100:	'GET_GIDS',
								0x10:	'GET_INSTRUMENTATION',
								0x20:	'GET_INTENT_FILTERS',
								0x80:	'GET_META_DATA',
								0x1000:	'GET_PERMISSIONS',
								0x8:	'GET_PROVIDERS',
								0x2:	'GET_RECEIVERS',
								0x40:	'GET_RESOLVED_FILTER',
								0x4:	'GET_SERVICES',
								0x400:	'GET_SHARED_LIBRARY_FILES',
								0x40:	'GET_SIGNATURES',
								0x2000: 'GET_UNINSTALLED_PACKAGES',
								0x800: 	'GET_URI_PERMISSION_PATTERNS'
							}
