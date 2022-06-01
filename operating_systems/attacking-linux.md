# attacking linux

## Privilege Escalation

### Commands

- list suid programs
```
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -l {} \; 2>/dev/null >suidfiles.txt
```

- list suid programs owned by root
```
find / -type f  -user root \( -perm -4000 -o -perm -2000 \) -exec ls -lg {} \; 2>/dev/null >suidfiles.txt
```

- list world writeable files in /etc
```
find /etc/ -type f -perm -o=w
```

- list world writeable files in /var
```
find /var/ -type f -perm -o=w
```

- list log files that are world readable
```
find /var/log/ -type f -perm -o=r
```


### Enumeration Scripts

- LinEnum
	- https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
	- https://github.com/rebootuser/LinEnum

- linuxprivchecker
	- https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
	- https://github.com/sleventyeleven/linuxprivchecker

### search for capabilities
	- using `getcap`
		- you might have to copy this binary onto the system.
		- you actually don't need to be a privileged user to read capabilies from a file's xattrs.
	- `getcap -r /`

### Kernel Exploits

- https://github.com/lucyoa/kernel-exploits
