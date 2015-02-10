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

# Global imports
import sys, logging
from io import BytesIO
from xml.etree.ElementTree import ElementTree


# Androguard imports
from StaticAnalyzer.tools.androguard.core.analysis import analysis
from StaticAnalyzer.tools.apkinfo.apk import *

# Androwarn modules import
from StaticAnalyzer.tools.apkinfo.core import *
from StaticAnalyzer.tools.apkinfo.api_constants import *
from StaticAnalyzer.tools.apkinfo.util import *

# Logguer
log = logging.getLogger('log')

# -- Voice Record -- #
def detect_MediaRecorder_Voice_record(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""	
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/media/MediaRecorder","setAudioSource", ".")	
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)
		
		if len(registers) > 0 :
			audio_source_int 	= int(get_register_value(1, registers)) # 1 is the index of the PARAMETER called in the method
			audio_source_name 	= get_constants_name_from_value(MediaRecorder_AudioSource, audio_source_int)
			
			local_formatted_str = "This application records audio from the '%s' source " % audio_source_name
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)
		
	return formatted_str

# -- Video Record -- #
def detect_MediaRecorder_Video_capture(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""	
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/media/MediaRecorder","setVideoSource", ".")	
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		if len(registers) > 0 :
			video_source_int 	= int(get_register_value(1, registers)) # 1 is the index of the PARAMETER called in the method
			video_source_name 	= get_constants_name_from_value(MediaRecorder_VideoSource, video_source_int)
			
			local_formatted_str = "This application captures video from the '%s' source" % video_source_name
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)
	

	return formatted_str

def gather_audio_video_eavesdropping(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend ( detect_MediaRecorder_Voice_record(x) )
	result.extend ( detect_MediaRecorder_Video_capture(x) )
	
	return result
def detect_Library_loading(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []

	structural_analysis_results = x.tainted_packages.search_methods("Ljava/lang/System","loadLibrary", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)		
		local_formatted_str = "This application loads a native library" 
		
		# If we're lucky enough to directly have the library's name
		if len(registers) == 1 :
			local_formatted_str = "%s: '%s'" % (local_formatted_str, get_register_value(0, registers))
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str


def detect_UNIX_command_execution(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Ljava/lang/Runtime","exec", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)
				
		local_formatted_str = "This application executes a UNIX command" 
		
		# If we're lucky enough to have the arguments
		if len(registers) >= 2 :
			local_formatted_str = "%s containing this argument: '%s'" % (local_formatted_str, get_register_value(1, registers))

		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str

def gather_code_execution(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend( detect_Library_loading(x) )
	result.extend( detect_UNIX_command_execution(x) )
		
	return result

def detect_Connectivity_Manager_leakages(x):
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	
	class_listing = [
			("getActiveNetworkInfo()",		"This application reads details about the currently active data network"),
			("isActiveNetworkMetered()", 	"This application tries to find out if the currently active data network is metered")
	]
	
	class_name = 'Landroid/net/ConnectivityManager'
	
	return bulk_structural_analysis(class_name, class_listing, x)
 
def detect_WiFi_Credentials_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	# This functions aims some HTC android devices 
	# Several HTC devices suffered from a bug allowing to dump wpa_supplicant.conf file containing clear text credentials
	# http://www.kb.cert.org/vuls/id/763355
	
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/net/wifi/WifiConfiguration","toString", ".")
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads the WiFi credentials" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)

		
	return formatted_str	

def gather_connection_interfaces_exfiltration(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend( detect_WiFi_Credentials_lookup(x) )
	result.extend( detect_Connectivity_Manager_leakages(x) )
	
	return result



def detect_log(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/util/Log","d|e|i|v|w|wtf", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)		

		if len(registers) >= 2 :
			tag 	= get_register_value(0, registers)
			message = get_register_value(1, registers)
			
			if isnt_all_regs_values([tag,message]) :
				local_formatted_str = "This application logs the message '%s' under the tag '%s'" % (message, tag)
				if not(local_formatted_str in formatted_str) :
					formatted_str.append(local_formatted_str)
	
	return formatted_str

def detect_get_package_info(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/content/pm/PackageManager","getPackageInfo", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)		

		if len(registers) >= 2 :
			package_name = get_register_value(1, registers)
			flag = get_register_value(2, registers)
			
			# Recover OR bitwise options set from the integer value, for instance 'GET_ACTIVITIES | GET_RECEIVERS'
			flags = recover_bitwise_flag_settings(flag, PackageManager_PackageInfo)
			
			local_formatted_str = "This application retrieves '%s' information about the '%s' application installed on the system" % (flags, package_name)
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)
	
	return formatted_str

def gather_device_settings_harvesting(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend( detect_log(x) )
	result.extend( detect_get_package_info(x) )
	
	return result

def detect_Location_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/location/LocationManager","getProviders", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)	
		
		local_formatted_str = "This application reads location information from all available providers (WiFi, GPS etc.)" 
		
		# we want only one occurence
		if not(local_formatted_str in formatted_str) :
			formatted_str.append(local_formatted_str)
		
	return formatted_str

def gather_location_lookup(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend( detect_Location_lookup(x) )
	
	return result


def detect_ContactAccess_lookup(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	detector_1 = search_field(x, "Landroid/provider/ContactsContract$CommonDataKinds$Phone;")
		
	detectors = [detector_1]
	
	if detector_tab_is_not_empty(detectors) :
		local_formatted_str = 'This application reads or edits contact data'
		formatted_str.append(local_formatted_str)
		
		for res in detectors :
			if res :
				try :
					log_result_path_information(res, "Contact access", "field")
				except :
					log.warn("Detector result '%s' is not a PathVariable instance" % res)
					
	return formatted_str


def detect_Telephony_SMS_read(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	detector_1 = search_string(x, "content://sms/inbox")
		
	detectors = [detector_1]
	
	if detector_tab_is_not_empty(detectors) :
		local_formatted_str = 'This application reads the SMS inbox'
		formatted_str.append(local_formatted_str)
		
		for res in detectors :
			if res :
				try :
					log_result_path_information(res, "SMS Inbox", "string")
				except :
					log.warn("Detector result '%s' is not a PathVariable instance" % res) 
		
	return formatted_str


def gather_PIM_data_leakage(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend( detect_ContactAccess_lookup(x) )
	result.extend( detect_Telephony_SMS_read(x) )
		
	return result

def detect_Socket_use(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Ljava/net/Socket","<init>", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)

		if len(registers) >= 2 :
			remote_address 	= get_register_value(1, registers) # 1 is the index of the PARAMETER called in the method
			remote_port		= get_register_value(2, registers)
			
			local_formatted_str = "This application opens a Socket and connects it to the remote address '%s' on the '%s' port " % (remote_address, remote_port)
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)		
	
	return formatted_str

def gather_suspicious_connection_establishment(x) :	
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend( detect_Socket_use(x) ) 
		
	return result
def detect_telephony_gsm_GsmCellLocation(x):
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	
	class_listing = [
			("getLac()",	"This application reads the Location Area Code value"),
			("getCid()",	"This application reads the Cell ID value")
	]
	
	class_name = 'Landroid/telephony/gsm/GsmCellLocation'
	
	return bulk_structural_analysis(class_name, class_listing, x)

def detect_Telephony_Manager_Leakages(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	
	class_listing = [
			("getCallState()", 				"This application reads the phone's current state"),
			("getCellLocation()", 			"This application reads the current location of the device"),
			("getDataActivity()", 			"This application reads the type of activity on a data connection"),
			("getDataState()", 				"This application reads the current data connection state"),
			("getDeviceId()", 				"This application reads the unique device ID, i.e the IMEI for GSM and the MEID or ESN for CDMA phones"),
			("getDeviceSoftwareVersion()", 	"This application reads the software version number for the device, for example, the IMEI/SV for GSM phones"),
			("getLine1Number()", 			"This application reads the phone number string for line 1, for example, the MSISDN for a GSM phone"),
			("getNeighboringCellInfo()", 	"This application reads the neighboring cell information of the device"),
			("getNetworkCountryIso()", 		"This application reads the ISO country code equivalent of the current registered operator's MCC (Mobile Country Code)"),
			("getNetworkOperator()", 		"This application reads the numeric name (MCC+MNC) of current registered operator"),
			("getNetworkOperatorName()", 	"This application reads the operator name"),
			("getNetworkType()", 			"This application reads the radio technology (network type) currently in use on the device for data transmission"),
			("getPhoneType()", 				"This application reads the device phone type value"),
			("getSimCountryIso()", 			"This application reads the ISO country code equivalent for the SIM provider's country code"),
			("getSimOperator()", 			"This application reads the MCC+MNC of the provider of the SIM"),
			("getSimOperatorName()", 		"This application reads the Service Provider Name (SPN)"),
			("getSimSerialNumber()", 		"This application reads the SIM's serial number"),
			("getSimState()", 				"This application reads the constant indicating the state of the device SIM card"),
			("getSubscriberId()", 			"This application reads the unique subscriber ID, for example, the IMSI for a GSM phone"),
			("getVoiceMailAlphaTag()", 		"This application reads the alphabetic identifier associated with the voice mail number"),
			("getVoiceMailNumber()", 		"This application reads the voice mail number")
	]
	
	class_name = 'Landroid/telephony/TelephonyManager'
	
	return bulk_structural_analysis(class_name, class_listing, x)

def gather_telephony_identifiers_leakage(x) :
	"""
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []

	result.extend( detect_Telephony_Manager_Leakages(x) )
	result.extend( detect_telephony_gsm_GsmCellLocation(x) )
	
	return result

# -- SMS Abuse -- #
def detect_Telephony_SMS_abuse(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	structural_analysis_results = x.tainted_packages.search_methods("Landroid/telephony/SmsManager","sendTextMessage", ".")
	
	for result in xrange(len(structural_analysis_results)) :
		registers = data_flow_analysis(structural_analysis_results, result, x)		
		
		if len(registers) > 3 :
			target_phone_number = get_register_value(1, registers)
			sms_message 		= get_register_value(3, registers)
			
			local_formatted_str = "This application sends an SMS message '%s' to the '%s' phone number" % (sms_message, target_phone_number)
			if not(local_formatted_str in formatted_str) :
				formatted_str.append(local_formatted_str)
	return formatted_str

def detect_SMS_interception(a,x) :
	"""
		@param a : an APK  instance
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	tree = ElementTree()
	
	try :
		manifest = AXMLPrinter( a.zip.read("AndroidManifest.xml") ).getBuff()
	
		tree.parse(BytesIO(manifest))
		
		root = tree.getroot()
					
		for parent, child, grandchild in get_parent_child_grandchild(root):
			
			# Criteria 1: "android.provider.Telephony.SMS_RECEIVED" + "intentfilter 'android:priority' a high number" => SMS interception
			if '{http://schemas.android.com/apk/res/android}name' in grandchild.attrib.keys() :
				
				if grandchild.attrib['{http://schemas.android.com/apk/res/android}name'] == "android.provider.Telephony.SMS_RECEIVED" :
					
					if child.tag == 'intentfilter' and '{http://schemas.android.com/apk/res/android}priority' in child.attrib.keys() :
						formatted_str.append("This application intercepts your incoming SMS")
						
						# Grab the interceptor's class name
						class_name = parent.attrib['{http://schemas.android.com/apk/res/android}name']
						package_name = a.package
						
						# Convert("com.test" + "." + "interceptor") to "Lcom/test/interceptor"
						class_name = convert_canonical_to_dex(package_name + "." + class_name[1:])
						
						# Criteria 2: if we can find 'abortBroadcast()' call => notification deactivation
						structural_analysis_results = x.tainted_packages.search_methods(class_name,"abortBroadcast", ".")
						if structural_analysis_results :
							formatted_str.append("This application disables incoming SMS notifications")
					
	except Exception, e :
		pass
	
	return formatted_str

def detect_Telephony_Phone_Call_abuse(x) :
	"""
		@param x : a VMAnalysis instance
		
		@rtype : a list of formatted strings
	"""
	formatted_str = []
	
	detector_1 = search_string(x, "android.intent.action.CALL")
	detector_2 = search_string(x, "android.intent.action.DIAL")
		
	detectors = [detector_1, detector_2]
	
	if detector_tab_is_not_empty(detectors) :
		local_formatted_str = 'This application makes phone calls'
		formatted_str.append(local_formatted_str)
		
		for res in detectors :
			if res :
				try :
					log_result_path_information(res, "Call Intent", "string")
				except :
					pass
		
	return formatted_str


def gather_telephony_services_abuse(a,x) :
	"""
		@param a : an APK  instance
		@param x : a VMAnalysis instance
	
		@rtype : a list strings for the concerned category, for exemple [ 'This application makes phone calls', "This application sends an SMS message 'Premium SMS' to the '12345' phone number" ]
	"""
	result = []
	
	result.extend( detect_Telephony_Phone_Call_abuse(x) )
	result.extend( detect_SMS_interception(a,x) )
	result.extend( detect_Telephony_SMS_abuse(x) )
	
	return result


