# AutoVAPT — Lab Setup Guide

This guide sets up a safe, isolated test environment to run AutoVAPT against intentionally vulnerable targets.

> **You must never run AutoVAPT against systems you don't own. This lab uses offline VMs for all testing.**

---

## Architecture

```
VirtualBox Host-Only Network: 192.168.56.0/24
─────────────────────────────────────────────
┌──────────────────────┐    ┌─────────────────────────┐
│  Kali Linux          │    │  Metasploitable 2        │
│  192.168.56.100      │◄──►│  192.168.56.101          │
│  (AutoVAPT runs here)│    │  (primary target)        │
└──────────────────────┘    └─────────────────────────┘
                                ┌─────────────────────┐
                                │  DVWA (Docker)       │
                                │  192.168.56.102      │
                                │  (web app target)    │
                                └─────────────────────┘
```

---

## Step 1 — Install VirtualBox

```bash
sudo apt install virtualbox virtualbox-ext-pack -y
```

Or download from: https://www.virtualbox.org/wiki/Downloads

---

## Step 2 — Download Metasploitable 2

1. Download from SourceForge:
   https://sourceforge.net/projects/metasploitable/files/Metasploitable2/

2. Extract the `.zip` — you'll get a `.vmdk` disk file.

3. In VirtualBox:
   - **New VM** → Linux → Ubuntu (32-bit)
   - RAM: 512 MB
   - Use existing disk → select the `.vmdk` file
   - Network: **Host-Only Adapter** → `vboxnet0`

4. Boot and login: `msfadmin / msfadmin`

5. Check IP: `ifconfig eth0` — should be `192.168.56.101`

---

## Step 3 — Set Up DVWA (Docker)

On your Kali machine:

```bash
# Install Docker if not present
sudo apt install docker.io -y
sudo systemctl start docker

# Pull and run DVWA
sudo docker run -d \
  --name dvwa \
  -p 192.168.56.102:80:80 \
  vulnerables/web-dvwa

# Verify it's running
sudo docker ps
```

Access DVWA at: `http://192.168.56.102/`
Default login: `admin / password`

> In DVWA → Setup/Reset DB → click **Create / Reset Database**
> Set Security Level to **Low** for initial testing.

---

## Step 4 — Configure Host-Only Network in VirtualBox

```bash
# Create vboxnet0 if it doesn't exist
sudo vboxmanage hostonlyif create
sudo vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1 --netmask 255.255.255.0

# Assign static IP on Kali
sudo ip addr add 192.168.56.100/24 dev eth0   # adjust interface as needed
```

Or via VirtualBox GUI: **File → Host Network Manager → Create → Configure**

---

## Step 5 — Verify Connectivity

```bash
# From Kali, ping both targets
ping -c 2 192.168.56.101    # Metasploitable
ping -c 2 192.168.56.102    # DVWA

# Quick nmap check
nmap -sn 192.168.56.0/24
```

---

## Step 6 — Start Metasploit RPC Daemon

```bash
cd /path/to/AutoVAPT
./scripts/start_msfrpcd.sh
```

---

## Step 7 — Run AutoVAPT

```bash
# Full scan against Metasploitable 2
python3 main.py --target 192.168.56.101 --mode full --intensity medium

# Web scan against DVWA
python3 main.py --target 192.168.56.102 --mode full --intensity high

# Recon only across the whole subnet
python3 main.py --target 192.168.56.0/24 --mode recon
```

Reports will be generated in `./reports/`.

---

## Expected Findings on Metasploitable 2

| Finding | Severity | CVE |
|---|---|---|
| vsftpd 2.3.4 Backdoor | CRITICAL | CVE-2011-2523 |
| EternalBlue SMB RCE | CRITICAL | CVE-2017-0144 |
| Unreal IRCd Backdoor | CRITICAL | CVE-2010-2075 |
| distcc Remote Code Execution | HIGH | CVE-2004-2687 |
| FTP Anonymous Login | HIGH | — |
| Weak SSH keys | MEDIUM | CVE-2008-0166 |
| Telnet exposed | MEDIUM | — |

---

## Cleanup

```bash
# Stop DVWA container
sudo docker stop dvwa && sudo docker rm dvwa

# Power off Metasploitable
# (from the VM console: sudo shutdown -h now)

# Kill msfrpcd
kill $(cat /tmp/msfrpcd.pid)
```

---

## Troubleshooting

**Metasploitable has no network:**
- Check VirtualBox network adapter is set to Host-Only (`vboxnet0`)
- Run `sudo dhclient eth0` inside the Metasploitable VM

**Docker DVWA not accessible:**
- Check `sudo docker ps` — container must be running
- Try `http://localhost/` first to confirm Docker is working

**msfrpcd connection refused:**
- Run `./scripts/start_msfrpcd.sh` and wait for the confirmation message
- Check `/tmp/msfrpcd.log` for errors
