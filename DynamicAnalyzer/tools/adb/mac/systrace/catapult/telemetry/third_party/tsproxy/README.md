# tsproxy
Traffic-shaping SOCKS5 proxy

tsproxy provides basic latency, download and upload traffic shaping while only requiring user-level access (no root permissions required).  It should work for basic browser testing but for protocol-level work it does not provide a suitable replacement for something like dummynet or netem.

tsproxy is monolithic and all of the functionality is in tsproxy.py.  It is written expecting Python 2.7.

#Usage
```bash
$ python tsproxy.py --rtt=<latency> --inkbps=<download bandwidth> --outkbps=<upload bandwidth>
```
Hit `ctrl-C` (or send a `SIGINT`) to exit

#Example
```bash
$ python tsproxy.py --rtt=200 --inkbps=1600 --outkbps=768
```

#Command-line Options


| Option            | Alias    | Description                              |
| ----------------- | -------- | ---------------------------------------- |
| **`--rtt`**       | **`-r`** | Latency in milliseconds (full round trip, half of the latency gets applied to each direction). |
| **`--inkbps`**    | **`-i`** | Download Bandwidth (in 1000 bits/s - Kbps). |
| **`--outkbps`**   | **`-o`** | Upload Bandwidth (in 1000 bits/s - Kbps). |
| **`--window`**    | **`-w`** | Emulated TCP initial congestion window (defaults to 10). |
| **`--port`**      | **`-p`** | SOCKS 5 proxy port (defaults to port 1080). Specifying a port of 0 will use a randomly assigned port. |
| **`--bind`**      | **`-b`** | Interface address to listen on (defaults to localhost). |
| **`--desthost`**  | **`-d`** | Redirect all outbound connections to the specified host (name or IP). |
| **`--mapports`**  | **`-m`** | Remap outbound ports. Comma-separated list of original:new with * as a wildcard. `--mapports '443:8443,*:8080'` |
| **`--localhost`** | **`-l`** | Include connections already destined for localhost/127.0.0.1 in the host and port remapping. |
| **`--verbose`**   | **`-v`** | Increase verbosity (specify multiple times for more). `-vvvv` for full debug output. |


#Runtime Options
The traffic shaping configuration can be changed dynamically at runtime by passing commands in through the console (or stdin).  Each command is on a line, terminated with an end-of-line (`\n`).


* **`flush`** : Flush queued data out of the pipes.  Useful for clearing out any accumulated background data between tests.
* **`set rtt <latency>`** : Change the connection latency. i.e. `set rtt 200\n` will change to a 200ms RTT.
* **`set inkbps <bandwidth>`** : Change the download bandwidth. i.e. `set inkbps 5000\n` will change to a 5Mbps download connection.
* **`set outkbps <bandwidth>`** : Change the upload bandwidth. i.e. `set outkbps 1000\n` will change to a 1Mbps upload connection.
* **`set mapports <port mapping string>`** : Change the destination port mapping.
* **`reset all`** : Disable all port mapping and traffic shaping
* **`reset rtt`** : Set latency to 0
* **`reset inkbps`** : Disable download traffic shaping
* **`reset outkbps`** : Disable upload traffic shaping
* **`reset mapports`** : Disable destination port mapping

All bandwidth and latency changes also carry an implied flush and clear out any pending data.


#Configuring Chrome to use tsproxy
Add a --proxy-server command-line option.
```bash
--proxy-server="socks://localhost:1080"
```

#Known Shortcomings/Issues
* DNS lookups on OSX (and FreeBSD) will block each other when it comes to actually resolving.  DNS in Python on most platforms is allowed to run concurrently in threads (which tsproxy does) but on OSX and FreeBSD it is not thread-safe and there is a lock around the actual lookups.  For most cases this isn't an issue because the latency isn't added on the actual DNS lookup (it is from the browser perspective but it is added outside of the actual lookup). This is also not an issue when desthost is used to override the destination address since dns lookups will be disabled.
* QUIC support. Chrome [doesn't currently support QUIC proxies](https://bugs.chromium.org/p/chromium/issues/detail?id=335275), and further work would be neccessary to correctly handle UDP traffic in tsproxy.
