Footprinting:
```
└─$ nmap -sV -A -p- 10.10.11.189            
Starting Nmap 7.93 ( https://nmap.org ) at 2023-05-10 22:17 EDT
Nmap scan report for precious.htb (10.10.11.189)
Host is up (0.030s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 845e13a8e31e20661d235550f63047d2 (RSA)
|   256 a2ef7b9665ce4161c467ee4e96c7c892 (ECDSA)
|_  256 33053dcd7ab798458239e7ae3c91a658 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Convert Web Page to PDF
| http-server-header: 
|   nginx/1.18.0
|_  nginx/1.18.0 + Phusion Passenger(R) 6.0.15
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.21 seconds
```

Enumerating HTTP service:
```
curl http://10.10.11.189:80/ -L
curl: (6) Could not resolve host: precious.htb
```

Local machine is not able to resolve the hostname for the redirect:
```
vim /etc/hosts
10.10.11.189    precious.htb 
```

The application will process the passed URL and generate a PDF:
![[PreciousWebApp.png]]
