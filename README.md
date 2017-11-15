---------------------------------------------
RPLMaster
---------------------------------------------

Author: ouned  
Version: 1.2

Description:
This is a masterserver for the quake3 protocol with advanced features:
- copy IP's from other masterservers
- maximum servers per IP
- maximum requests per IP per second
- backup servers to a file which is used to restore IP's on a crash
- clients can request some more information about the master:
    - "ÿÿÿÿmaster": returns e.g. "RPLMaster v1.2"
    - "ÿÿÿÿstats version": returns e.g. "1.2"
    - "ÿÿÿÿstats startup": returns unix timestamp of when the master was startet
    - "ÿÿÿÿstats reqs":    returns number of requests ("ÿÿÿÿgetservers...") since startup
    - "ÿÿÿÿgetservers 16 heartbeaters": only returns servers which heartbeat the master directly (are not copied from another master)

Installation:
Run the rplmaster executable for your platform including the name of your configuration file and the name for your backup file.
e.g. rplmaster.exe jk2.cfg jk2.bak
See the configuration file for more details.

Changelog:  
1.2:
- increased max source masters from 10 to 16
- sends 256 servers at max in a single packet
- corrected some smaller bugs
- supports dpmaster as a sourcemaster
- stats requests

License:  
GPLv3 (http://www.gnu.org/licenses/gpl.html)  
Sourcecode can be found in the "src" directory


Example servers for JK2 and JKA are running @ master.jk2mv.org
