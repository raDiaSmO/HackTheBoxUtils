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

By testing the behavior of the web application, we can see that without the Auto redirect option enabled, there is a POST request with a controllable parameter sent to the /search endpoint:
```http
POST /search HTTP/1.1
Host: searcher.htb
Content-Length: 59
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

engine=Accuweather&query=http%3A%2F%2F10.10.14.20%3A8000%2F
```