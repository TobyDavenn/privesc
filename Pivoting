 <h2> Proxying </h2> <br>
 
  If you have a MSFCONSOLE shell on a machine (generate payload via msfvenom if needed and run and set multi/handler on msfconsole <br>
  background session -- background <br>
  use post/multi/manage/autoroute <br>
  set SESSION 1 (change if more than 1 session) <br>
  set SUBNET 10.200.3.0 (change to submet needed) <br>
  exploit <br>
  msfconsole<br>
pivoting, check ifconfig when you have a shell on the machine if you have a meterpreter shell, are there multiple nics?<br>
if yes, use autoroute<br>
background session -- background<br>
use post/multi/manage/autoroute<br>
set SESSION 1 (change if more than 1 session)<br>
set SUBNET 10.200.3.0 (change to submet needed)<br>
exploit<br>
if that doesnt work make sure your back in your session and run (change IPs) -- meterpreter > run autoroute -s 192.181.243.1/24 <br>
now you can use further auxiliary commands against the machine pivoting towards<br>
has nmap command which can be used with script comnmand --script(useful for pivoting)<br>
  background <br>
  for portscan - use auxiliary/scanner/portscan/tcp <br>
  set options and set everything <br>
  run <br>
  Identify ports of interest, now need to configure port forward. <br>
  access the session -- sessions -i NUMBER <br>
  ensure meterpreter shell and type -- portfwd add -l (PORT TO FORWARD, e.g. 555) -p (PORT ATTACKING) -r victimIP <br>
  background session <br>
  Now perform nmap -sV -sC scan on ported for e.g. -p 555 localhost still in msfconsole console
  Once found an exploit for version type -- search SERVICE and use whatever exploit <br>
  set IP to actual machines ip 
  exploit 
  
  
  <h2> Proxychains </h2>
  <br>
   If you have a MSFCONSOLE shell on a machine (generate payload via msfvenom if needed and run and set multi/handler on msfconsole <br>
  background session -- background <br>
  use post/multi/manage/autoroute <br>
  set SESSION 1 (change if more than 1 session) <br>
  set SUBNET 10.200.3.0 (change to submet needed) <br>
  exploit <br>
  Now setup proxy <br>
 use auxiliary/server/socks_proxy <br>
 set VERSION 4a <br>
  type -- run <br>
 should not need to edit conf as working on my machine (/etc/proxychains.conf) <br>
 type --- proxychains nmap -T4 IP/CIDR and look for "OK" <br>
 every command is the same just add proxychains before
  
