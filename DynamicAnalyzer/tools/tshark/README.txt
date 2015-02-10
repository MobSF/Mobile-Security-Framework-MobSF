$Id$

General Information
------- -----------

Wireshark is a network traffic analyzer, or "sniffer", for Unix and
Unix-like operating systems.  It uses GTK+, a graphical user interface
library, and libpcap, a packet capture and filtering library.

The Wireshark distribution also comes with TShark, which is a
line-oriented sniffer (similar to Sun's snoop, or tcpdump) that uses the
same dissection, capture-file reading and writing, and packet filtering
code as Wireshark, and with editcap, which is a program to read capture
files and write the packets from that capture file, possibly in a
different capture file format, and with some packets possibly removed
from the capture.

The official home of Wireshark is

    http://www.wireshark.org

The latest distribution can be found in the subdirectory

    http://www.wireshark.org/download


Installation
------------

Wireshark is known to compile and run on the following systems:

  - Linux (2.0 and later kernels, various distributions)
  - Solaris (2.5.1 and later)
  - FreeBSD (2.2.5 and later)
  - NetBSD
  - OpenBSD
  - Mac OS X (10.2 and later)
  - HP-UX (10.20, 11.00, 11.11)
  - Sequent PTX v4.4.5  (Nick Williams <njw@sequent.com>)
  - Tru64 UNIX (formerly Digital UNIX) (3.2 and later)
  - Irix (6.5)
  - AIX (4.3.2, with a bit of work)
  - Windows (2003, XP, Vista, 7)

and possibly on other versions of those OSes.  It should run on other
Unix-ish systems without too much trouble.

If you have an older version of the operating systems listed above, it
might be supported by an older version of Wireshark. In particular,
Windows 2000 is supported by Wireshark 1.2.x, Windows NT 4.0 is supported by
Wireshark 0.99.4, and Windows 95, 98, and ME are supported by Ethereal 0.99.0.

NOTE: the Makefile appears to depend on GNU "make"; it doesn't appear to
work with the "make" that comes with Solaris 7 nor the BSD "make".
Perl is also needed to create the man page.

If you decide to modify the yacc grammar or lex scanner, then
you need "flex" - it cannot be built with vanilla "lex" -
and either "bison" or the Berkeley "yacc". Your flex
version must be 2.5.1 or greater. Check this with 'flex -V'.

If you decide to modify the NetWare Core Protocol dissector, you
will need python, as the data for packet types is stored in a python
script, ncp2222.py.

You must therefore install Perl, GNU "make", "flex", and either "bison" or
Berkeley "yacc" on systems that lack them.

Full installation instructions can be found in the INSTALL file.
         
See also the appropriate README.<OS> files for OS-specific installation
instructions.

Usage
-----          

In order to capture packets from the network, you need to make the
dumpcap program set-UID to root, or you need to have access to the
appropriate entry under /dev if your system is so inclined (BSD-derived
systems, and systems such as Solaris and HP-UX that support DLPI,
typically fall into this category).  Although it might be tempting to
make the Wireshark and TShark executables setuid root, or to run them as
root please don't.  The capture process has been isolated in dumpcap;
this simple program is less likely to contain security holes, and thus
safer to run as root.

Please consult the man page for a description of each command-line
option and interface feature.


Multiple File Types
-------------------

The wiretap library is a packet-capture library currently under
development parallel to wireshark.  In the future it is hoped that
wiretap will have more features than libpcap, but wiretap is still in
its infancy. However, wiretap is used in wireshark for its ability
to read multiple file types.  See the Wireshark man page or the
Wireshark User's Guide for a list of supported file formats.

In addition, it can read gzipped versions of any of those files
automatically, if you have the zlib library available when compiling
Wireshark. Wireshark needs a modern version of zlib to be able to use
zlib to read gzipped files; version 1.1.3 is known to work.  Versions
prior to 1.0.9 are missing some functions that Wireshark needs and won't
work.  "./configure" should detect if you have the proper zlib version
available and, if you don't, should disable zlib support. You can always
use "./configure --disable-zlib" to explicitly disable zlib support.

Although Wireshark can read AIX iptrace files, the documentation on
AIX's iptrace packet-trace command is sparse.  The 'iptrace' command
starts a daemon which you must kill in order to stop the trace. Through
experimentation it appears that sending a HUP signal to that iptrace
daemon causes a graceful shutdown and a complete packet is written
to the trace file. If a partial packet is saved at the end, Wireshark
will complain when reading that file, but you will be able to read all
other packets.  If this occurs, please let the Wireshark developers know
at wireshark-dev@wireshark.org, and be sure to send us a copy of that trace
file if it's small and contains non-sensitive data.

Support for Lucent/Ascend products is limited to the debug trace output
generated by the MAX and Pipline series of products.  Wireshark can read
the output of the "wandsession" "wandisplay", "wannext", and "wdd"
commands. 

Wireshark can also read dump trace output from the Toshiba "Compact Router"
line of ISDN routers (TR-600 and TR-650). You can telnet to the router
and start a dump session with "snoop dump".

CoSine L2 debug output can also be read by Wireshark. To get the L2
debug output, get in the diags mode first and then use
"create-pkt-log-profile" and "apply-pkt-log-profile" commands under
layer-2 category. For more detail how to use these commands, you
should examine the help command by "layer-2 create ?" or "layer-2 apply ?".

To use the Lucent/Ascend, Toshiba and CoSine traces with Wireshark, you must 
capture the trace output to a file on disk.  The trace is happening inside 
the router and the router has no way of saving the trace to a file for you.
An easy way of doing this under Unix is to run "telnet <ascend> | tee <outfile>".
Or, if your system has the "script" command installed, you can save
a shell session, including telnet to a file. For example, to a file named
tracefile.out:

$ script tracefile.out
Script started on <date/time>
$ telnet router
..... do your trace, then exit from the router's telnet session.
$ exit
Script done on <date/time>



IPv6
----
If your operating system includes IPv6 support, wireshark will attempt to
use reverse name resolution capabilities when decoding IPv6 packets.

If you want to turn off name resolution while using wireshark, start
wireshark with the "-n" option to turn off all name resolution (including
resolution of MAC addresses and TCP/UDP/SMTP port numbers to names), or
with the "-N mt" option to turn off name resolution for all
network-layer addresses (IPv4, IPv6, IPX).

You can make that the default setting by opening the Preferences dialog
box using the Preferences item in the Edit menu, selecting "Name
resolution", turning off the appropriate name resolution options,
clicking "Save", and clicking "OK".

If you would like to compile wireshark without support for IPv6 name
resolution, use the "--disable-ipv6" option with "./configure".  If you
compile wireshark without IPv6 name resolution, you will still be able to
decode IPv6 packets, but you'll only see IPv6 addresses, not host names.


SNMP
----
Wireshark can do some basic decoding of SNMP packets; it can also use
the libsmi library to do more sophisticated decoding, by reading MIB
files and using the information in those files to display OIDs and
variable binding values in a friendlier fashion.  The configure script
will automatically determine whether you have the libsmi library on
your system.  If you have the libsmi library but _do not_ want to have
Wireshark use it, you can run configure with the "--without-libsmi"
option.

How to Report a Bug
-------------------
Wireshark is still under constant development, so it is possible that you will
encounter a bug while using it. Please report bugs at http://bugs.wireshark.org.
Be sure you enter into the bug:

	1) the complete build information from the "About Wireshark"
	   item in the Help menu or the output of "wireshark -v" for
	   Wireshark bugs and the output of "tshark -v" for TShark bugs;

	2) if the bug happened on Linux, the Linux distribution you were
	   using, and the version of that distribution;

	3) the command you used to invoke Wireshark, if you ran
	   Wireshark from the command line, or TShark, if you ran
	   TShark, and the sequence of operations you performed that
	   caused the bug to appear.

If the bug is produced by a particular trace file, please be sure to
attach to the bug a trace file along with your bug description.  If the
trace file contains sensitive information (e.g., passwords), then please
do not send it.

If Wireshark died on you with a 'segmentation violation', 'bus error',
'abort', or other error that produces a UNIX core dump file, you can
help the developers a lot if you have a debugger installed.  A stack
trace can be obtained by using your debugger ('gdb' in this example),
the wireshark binary, and the resulting core file.  Here's an example of
how to use the gdb command 'backtrace' to do so.

$ gdb wireshark core
(gdb) backtrace
..... prints the stack trace
(gdb) quit
$

The core dump file may be named "wireshark.core" rather than "core" on
some platforms (e.g., BSD systems).  If you got a core dump with
TShark rather than Wireshark, use "tshark" as the first argument to
the debugger; the core dump may be named "tshark.core".

Disclaimer
----------

There is no warranty, expressed or implied, associated with this product.
Use at your own risk.


Gerald Combs <gerald@wireshark.org>
Gilbert Ramirez <gram@alumni.rice.edu>
Guy Harris <guy@alum.mit.edu>
