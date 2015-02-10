-- init.lua
--
-- initialize wireshark's lua
--
--  This file is going to be executed before any other lua script.
--  It can be used to load libraries, disable functions and more.
--
-- $Id$
--
-- Wireshark - Network traffic analyzer
-- By Gerald Combs <gerald@wireshark.org>
-- Copyright 1998 Gerald Combs
--
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

-- Set disable_lua to true to disable Lua support.
disable_lua = false

if disable_lua then
    return
end

-- If set and we are running with special privileges this setting
-- tells whether scripts other than this one are to be run.
run_user_scripts_when_superuser = false


-- disable potentialy harmful lua functions when running superuser
if running_superuser then
    local hint = "has been disabled due to running Wireshark as superuser. See http://wiki.wireshark.org/CaptureSetup/CapturePrivileges for help in running Wireshark as an unprivileged user."
    local disabled_lib = {}
    setmetatable(disabled_lib,{ __index = function() error("this package ".. hint) end } );

    dofile = function() error("dofile " .. hint) end
    loadfile = function() error("loadfile " .. hint) end
    loadlib = function() error("loadlib " .. hint) end
    require = function() error("require " .. hint) end
    os = disabled_lib
    io = disabled_lib
    file = disabled_lib
end

-- to avoid output to stdout which can cause problems lua's print ()
-- has been suppresed so that it yields an error.
-- have print() call info() instead.
if gui_enabled() then
    print = info
end

function typeof(obj)
    local mt = getmetatable(obj)
    return mt and mt.__typeof or type(obj)
end

-- -- Wiretap encapsulations XXX
wtap_encaps = {
	["UNKNOWN"] = 0,
	["ETHERNET"] = 1,
	["TOKEN_RING"] = 2,
	["SLIP"] = 3,
	["PPP"] = 4,
	["FDDI"] = 5,
	["FDDI_BITSWAPPED"] = 6,
	["RAW_IP"] = 7,
	["ARCNET"] = 8,
	["ARCNET_LINUX"] = 9,
	["ATM_RFC1483"] = 10,
	["LINUX_ATM_CLIP"] = 11,
	["LAPB"] = 12,
	["ATM_PDUS"] = 13,
	["ATM_PDUS_UNTRUNCATED"] = 14,
	["NULL"] = 15,
	["ASCEND"] = 16,
	["ISDN"] = 17,
	["IP_OVER_FC"] = 18,
	["PPP_WITH_PHDR"] = 19,
	["IEEE_802_11"] = 20,
	["IEEE_802_11_PRISM"] = 21,
	["IEEE_802_11_WITH_RADIO"] = 22,
	["IEEE_802_11_RADIOTAP"] = 23,
	["IEEE_802_11_AVS"] = 24,
	["SLL"] = 25,
	["FRELAY"] = 26,
	["FRELAY_WITH_PHDR"] = 27,
	["CHDLC"] = 28,
	["CISCO_IOS"] = 29,
	["LOCALTALK"] = 30,
	["OLD_PFLOG"] = 31,
	["HHDLC"] = 32,
	["DOCSIS"] = 33,
	["COSINE"] = 34,
	["WFLEET_HDLC"] = 35,
	["SDLC"] = 36,
	["TZSP"] = 37,
	["ENC"] = 38,
	["PFLOG"] = 39,
	["CHDLC_WITH_PHDR"] = 40,
	["BLUETOOTH_H4"] = 41,
	["MTP2"] = 42,
	["MTP3"] = 43,
	["IRDA"] = 44,
	["USER0"] = 45,
	["USER1"] = 46,
	["USER2"] = 47,
	["USER3"] = 48,
	["USER4"] = 49,
	["USER5"] = 50,
	["USER6"] = 51,
	["USER7"] = 52,
	["USER8"] = 53,
	["USER9"] = 54,
	["USER10"] = 55,
	["USER11"] = 56,
	["USER12"] = 57,
	["USER13"] = 58,
	["USER14"] = 59,
	["USER15"] = 60,
	["SYMANTEC"] = 61,
	["APPLE_IP_OVER_IEEE1394"] = 62,
	["BACNET_MS_TP"] = 63,
	["NETTL_RAW_ICMP"] = 64,
	["NETTL_RAW_ICMPV6"] = 65,
	["GPRS_LLC"] = 66,
	["JUNIPER_ATM1"] = 67,
	["JUNIPER_ATM2"] = 68,
	["REDBACK"] = 69,
	["NETTL_RAW_IP"] = 70,
	["NETTL_ETHERNET"] = 71,
	["NETTL_TOKEN_RING"] = 72,
	["NETTL_FDDI"] = 73,
	["NETTL_UNKNOWN"] = 74,
	["MTP2_WITH_PHDR"] = 75,
	["JUNIPER_PPPOE"] = 76,
	["GCOM_TIE1"] = 77,
	["GCOM_SERIAL"] = 78,
	["NETTL_X25"] = 79,
	["K12"] = 80,
	["JUNIPER_MLPPP"] = 81,
	["JUNIPER_MLFR"] = 82,
	["JUNIPER_ETHER"] = 83,
	["JUNIPER_PPP"] = 84,
	["JUNIPER_FRELAY"] = 85,
	["JUNIPER_CHDLC"] = 86,
	["JUNIPER_GGSN"] = 87,
	["LINUX_LAPD"] = 88,
	["CATAPULT_DCT2000"] = 89,
	["BER"] = 90,
	["JUNIPER_VP"] = 91,
	["USB"] = 92,
	["IEEE802_16_MAC_CPS"] = 93,
	["NETTL_RAW_TELNET"] = 94,
	["USB_LINUX"] = 95,
	["MPEG"] = 96,
	["PPI"] = 97,
	["ERF"] = 98,
	["BLUETOOTH_H4_WITH_PHDR"] = 99,
	["SITA"] = 100,
	["SCCP"] = 101,
	["BLUETOOTH_HCI"] = 102,
	["IPMB"] = 103,
	["IEEE802_15_4"] = 104,
	["X2E_XORAYA"] = 105,
	["FLEXRAY"] = 106,
	["LIN"] = 107,
	["MOST"] = 108,
	["CAN20B"] = 109,
	["LAYER1_EVENT"] = 110,
	["X2E_SERIAL"] = 111,
	["I2C"] = 112,
	["IEEE802_15_4_NONASK_PHY"] = 113,
	["TNEF"] = 114,
	["USB_LINUX_MMAPPED"] = 115,
	["GSM_UM"] = 116,
	["DPNSS"] = 117,
	["PACKETLOGGER"] = 118,
	["NSTRACE_1_0"] = 119,
	["NSTRACE_2_0"] = 120,
	["FIBRE_CHANNEL_FC2"] = 121,
	["FIBRE_CHANNEL_FC2_WITH_FRAME_DELIMS"] = 122,
	["JPEG_JFIF"] = 123,
	["IPNET"] = 124,
	["SOCKETCAN"] = 125,
	["IEEE_802_11_NETMON"] = 126,
	["IEEE802_15_4_NOFCS"] = 127,
	["RAW_IPFIX"] = 128,
	["RAW_IP4"] = 129,
	["RAW_IP6"] = 130,
	["LAPD"] = 131,
	["DVBCI"] = 132,
	["MUX27010"] = 133,
	["MIME"] = 134,
	["NETANALYZER"] = 135,
	["NETANALYZER_TRANSPARENT"] = 136,
	["IP_OVER_IB"] = 137,
	["MPEG_2_TS"] = 138,
	["PPP_ETHER"] = 139,
	["NFC_LLCP"] = 140,
	["NFLOG"] = 141,
	["V5_EF"] = 142,
	["BACNET_MS_TP_WITH_PHDR"] = 143,
	["IXVERIWAVE"] = 144,
	["IEEE_802_11_AIROPEEK"] = 145,
	["SDH"] = 146,
	["DBUS"] = 147,
	["AX25_KISS"] = 148,
	["AX25"] = 149,
	["SCTP"] = 150,
	["INFINIBAND"] = 151,
	["JUNIPER_SVCS"] = 152,
	["USBPCAP"] = 153
}
wtap = wtap_encaps -- for bw compatibility


-- -- Wiretap file types
wtap_filetypes = {
	["UNKNOWN"] = 0,
	["PCAP"] = 1,
	["PCAPNG"] = 2,
	["PCAP_NSEC"] = 3,
	["PCAP_AIX"] = 4,
	["PCAP_SS991029"] = 5,
	["PCAP_NOKIA"] = 6,
	["PCAP_SS990417"] = 7,
	["PCAP_SS990915"] = 8,
	["5VIEWS"] = 9,
	["IPTRACE_1_0"] = 10,
	["IPTRACE_2_0"] = 11,
	["BER"] = 12,
	["HCIDUMP"] = 13,
	["CATAPULT_DCT2000"] = 14,
	["NETXRAY_OLD"] = 15,
	["NETXRAY_1_0"] = 16,
	["COSINE"] = 17,
	["CSIDS"] = 18,
	["DBS_ETHERWATCH"] = 19,
	["ERF"] = 20,
	["EYESDN"] = 21,
	["NETTL"] = 22,
	["ISERIES"] = 23,
	["ISERIES_UNICODE"] = 24,
	["I4BTRACE"] = 25,
	["ASCEND"] = 26,
	["NGSNIFFER_UNCOMPRESSED"] = 29,
	["NGSNIFFER_COMPRESSED"] = 30,
	["NETXRAY_1_1"] = 31,
	["NETWORK_INSTRUMENTS"] = 33,
	["LANALYZER"] = 34,
	["PPPDUMP"] = 35,
	["RADCOM"] = 36,
	["SNOOP"] = 37,
	["SHOMITI"] = 38,
	["VMS"] = 39,
	["K12"] = 40,
	["TOSHIBA"] = 41,
	["VISUAL_NETWORKS"] = 42,
	["PEEKCLASSIC_V56"] = 43,
	["PEEKCLASSIC_V7"] = 44,
	["PEEKTAGGED"] = 45,
	["MPEG"] = 46,
	["K12TEXT"] = 47,
	["NETSCREEN"] = 48,
	["COMMVIEW"] = 49,
	["BTSNOOP"] = 50,
	["TNEF"] = 51,
	["DCT3TRACE"] = 52,
	["PACKETLOGGER"] = 53,
	["DAINTREE_SNA"] = 54,
	["NETSCALER_1_0"] = 55,
	["NETSCALER_2_0"] = 56,
	["JPEG_JFIF"] = 57,
	["IPFIX"] = 58,
	["MIME"] = 59,
	["AETHRA"] = 60,
	["MPEG_2_TS"] = 61,
	["VWR_80211"] = 62,
	["VWR_ETH"] = 63,
	["CAMINS"] = 64,
	["TSPREC_SEC"] = 0,
	["TSPREC_DSEC"] = 1,
	["TSPREC_CSEC"] = 2,
	["TSPREC_MSEC"] = 3,
	["TSPREC_USEC"] = 6,
	["TSPREC_NSEC"] = 9
}


--  -- Field Types
ftypes = {
	["NONE"] = 0,
	["PROTOCOL"] = 1,
	["BOOLEAN"] = 2,
	["UINT8"] = 3,
	["UINT16"] = 4,
	["UINT24"] = 5,
	["UINT32"] = 6,
	["UINT64"] = 7,
	["INT8"] = 8,
	["INT16"] = 9,
	["INT24"] = 10,
	["INT32"] = 11,
	["INT64"] = 12,
	["FLOAT"] = 13,
	["DOUBLE"] = 14,
	["ABSOLUTE_TIME"] = 15,
	["RELATIVE_TIME"] = 16,
	["STRING"] = 17,
	["STRINGZ"] = 18,
	["UINT_STRING"] = 19,
	["ETHER"] = 20,
	["BYTES"] = 21,
	["UINT_BYTES"] = 22,
	["IPv4"] = 23,
	["IPv6"] = 24,
	["IPXNET"] = 25,
	["FRAMENUM"] = 26,
	["PCRE"] = 27,
	["GUID"] = 28,
	["OID"] = 29,
	["EUI64"] = 30,
	["AX25"] = 31
}


-- -- Display Bases
 base = {
	["NONE"] = 0,
	["DEC"] = 1,
	["HEX"] = 2,
	["OCT"] = 3,
	["DEC_HEX"] = 4,
	["HEX_DEC"] = 5,
}



-- -- Encodings
ENC_BIG_ENDIAN = 0
ENC_LITTLE_ENDIAN = 2147483648
ENC_TIME_TIMESPEC = 0
ENC_TIME_NTP = 2
ENC_CHARENCODING_MASK = 2147483646
ENC_ASCII = 0
ENC_UTF_8 = 2
ENC_UTF_16 = 4
ENC_UCS_2 = 6
ENC_EBCDIC = 8
ENC_NA = 0




-- -- Expert flags and facilities
PI_SEVERITY_MASK = 15728640
PI_COMMENT = 1048576
PI_CHAT = 2097152
PI_NOTE = 4194304
PI_WARN = 6291456
PI_ERROR = 8388608
PI_GROUP_MASK = 4278190080
PI_CHECKSUM = 16777216
PI_SEQUENCE = 33554432
PI_RESPONSE_CODE = 50331648
PI_REQUEST_CODE = 67108864
PI_UNDECODED = 83886080
PI_REASSEMBLE = 100663296
PI_MALFORMED = 117440512
PI_DEBUG = 134217728
PI_PROTOCOL = 150994944
PI_SECURITY = 167772160
PI_COMMENTS_GROUP = 184549376




-- -- menu groups for register_menu
MENU_ANALYZE_UNSORTED = 0
MENU_ANALYZE_CONVERSATION = 1
MENU_STAT_UNSORTED = 2
MENU_STAT_GENERIC = 3
MENU_STAT_CONVERSATION = 4
MENU_STAT_ENDPOINT = 5
MENU_STAT_RESPONSE = 6
MENU_STAT_TELEPHONY = 7
MENU_TOOLS_UNSORTED = 8


-- other useful constants
GUI_ENABLED = gui_enabled()
DATA_DIR = datafile_path()
USER_DIR = persconffile_path()

dofile(DATA_DIR.."console.lua")
--dofile(DATA_DIR.."dtd_gen.lua")
