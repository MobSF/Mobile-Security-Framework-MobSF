# -*- text -*-
##############################################################################
#
#	HP ProCurve VSA's
#
#	$Id$
#
##############################################################################

VENDOR		HP				11

#
# Attributes supported by HP ProCurve wired networking devices
#
BEGIN-VENDOR	HP

# Management authorization
ATTRIBUTE	HP-Privilege-Level			1	integer
ATTRIBUTE	HP-Command-String			2	string
ATTRIBUTE	HP-Command-Exception			3	integer
ATTRIBUTE	HP-Management-Protocol			26	integer

# Dynamic port-access attributes
ATTRIBUTE	HP-Port-Client-Limit-Dot1x		10	integer
ATTRIBUTE	HP-Port-Client-Limit-MA			11	integer
ATTRIBUTE	HP-Port-Client-Limit-WA			12	integer
ATTRIBUTE	HP-Port-Auth-Mode-Dot1x			13	integer

# Client QoS attributes
ATTRIBUTE	HP-Port-Priority-Regeneration-Table	40	string

# Access control
ATTRIBUTE	HP-Cos					40	string
#ATTRIBUTE	HP-Rate-Limit				46	integer

ATTRIBUTE	HP-Bandwidth-Max-Ingress		46	integer
ATTRIBUTE	HP-Bandwidth-Max-Egress			48	integer

ATTRIBUTE	HP-Ip-Filter-Raw			61	string

# Client ACL attributes
ATTRIBUTE	HP-Nas-Filter-Rule			61	string
ATTRIBUTE	HP-Nas-Rules-IPv6			63	integer

# VLAN assignment attributes
ATTRIBUTE	HP-Egress-VLANID			64	integer
ATTRIBUTE	HP-Egress-VLAN-Name			65	string

# See http://wiki.freeradius.org/HP#Capability_advertisements
ATTRIBUTE	HP-Capability-Advert			255	octets

# HP-Port-Auth-Mode-Dot1x Attribute Values
VALUE	HP-Port-Auth-Mode-Dot1x		Port-Based		1
VALUE	HP-Port-Auth-Mode-Dot1x		User-Based		2

# HP-Command-Exception Attribute Values
VALUE	HP-Command-Exception		Permit-List		0
VALUE	HP-Command-Exception		Deny-List		1

# HP-Management-Protocol
VALUE	HP-Management-Protocol		HTTP			5
VALUE	HP-Management-Protocol		HTTPS			6

#
#  Conflicting attributes are commented out.
#
#ATTRIBUTE	HP-Management-Role			26	integer

# HP-Management-Role
#VALUE	HP-Management-Role		SuperUser		1
#VALUE	HP-Management-Role		Monitor			2
#VALUE	HP-Management-Role		HelpDeskManager		16
#VALUE	HP-Management-Role		NetworkAdministrator	17
#VALUE	HP-Management-Role		SystemAdministrator	18
#VALUE	HP-Management-Role		WebUserAdminstrator	19

#	Privilege attributes for HP-GbE2c, HP 1:10Gb, and HP 10Gb
#	Ethernet Blade Switches
#
VALUE	Service-Type			HP-Oper			252
VALUE	Service-Type			HP-User			255

END-VENDOR	HP
