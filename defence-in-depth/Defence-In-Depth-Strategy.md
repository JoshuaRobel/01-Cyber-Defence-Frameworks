# Defence in Depth Strategy - Multi-Layer Cyber Defence Architecture

**Version:** 2.2  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Executive Summary

Defence in Depth is a security strategy that implements multiple, independent protective layers. If one layer fails, others remain active. This document provides practical implementation guidance for SOC teams.

---

## The Seven Layers of Defence in Depth

### Layer 1: PERIMETER DEFENCE (Network Edge)

**Objective:** Prevent unauthorized traffic from entering the network

**Components:**
```
┌─────────────────────────────────────────────┐
│  EXTERNAL INTERNET (Untrusted)              │
└────────────┬────────────────────────────────┘
             │
      ┌──────▼───────┐
      │ Firewall #1  │  (Primary)
      └──────┬───────┘
             │
    ┌────────▼────────┐
    │ DDoS Mitigation │  (ISP-level or CDN)
    └────────┬────────┘
             │
      ┌──────▼───────┐
      │ Web Filter   │  (URL/Content filtering)
      └──────┬───────┘
             │
    ┌────────▼────────────┐
    │ INTERNAL NETWORK    │
    └─────────────────────┘
```

**Key Controls:**

1. **Firewall Rules**
   ```
   Inbound Rules:
   ├─ DENY all by default (whitelist approach)
   ├─ ALLOW port 80 (HTTP) to web servers only
   ├─ ALLOW port 443 (HTTPS) to web servers only
   ├─ ALLOW port 22 (SSH) to management servers, specific IPs only
   ├─ ALLOW port 3389 (RDP) from VPN gateway only
   └─ ALLOW DNS (port 53) from internal DNS servers
   
   Outbound Rules:
   ├─ DENY all non-approved destinations by default
   ├─ ALLOW port 80 (HTTP) to approved web content
   ├─ ALLOW port 443 (HTTPS) to approved sites
   ├─ ALLOW DNS (port 53) to internal DNS only
   ├─ ALLOW NTP (port 123) for time sync
   └─ ALLOW mail relay (port 25/587) to approved MTA only
   ```

2. **IDS/IPS Configuration**
   ```
   Alert Thresholds:
   ├─ Port scan detection: SYN to 20+ closed ports in 60s
   ├─ DDoS detection: 1000+ connection attempts from single IP
   ├─ Known malware signatures: Block (not alert)
   ├─ SQL injection attempts: Block + Alert
   └─ Cross-site scripting (XSS): Block + Alert
   
   Action Levels:
   ├─ BLOCK: Known malware, SQL injection, buffer overflows
   ├─ ALERT: Port scans, unusual traffic patterns
   └─ LOG: All traffic (for forensics)
   ```

3. **DDoS Mitigation**
   ```
   Detection Mechanisms:
   ├─ Volumetric attack: >1 Gbps traffic spike
   ├─ Protocol attack: Malformed packets, SYN floods
   ├─ Application-layer: HTTP floods to specific URL
   
   Mitigation Techniques:
   ├─ Rate limiting: Max connections per IP
   ├─ Blackhole routing: Drop malicious traffic at ISP
   ├─ Geographic blocking: Block countries not in business scope
   └─ CDN failover: Distribute traffic across CDN nodes
   ```

**Detection Metrics:**
```
Firewall Log Analysis (Monthly):
├─ Blocked connections: Should be >95% of all denied traffic
├─ Top blocked ports: Should be non-business ports (3389, 445, 139)
├─ Top blocked IPs: Geographic analysis (Russia, China, Iran if applicable)
└─ Anomalies: Sudden spike in port X attempts = possible attack

Splunk Query for Suspicious Inbound:
index=firewall action=deny 
| stats count by dst_port, src_country 
| where count > 1000 
| sort - count
```

**Defence in Depth Layer 1 Checklist:**
```
☐ Firewall deployed at network edge
☐ Default-deny inbound policy configured
☐ Default-deny outbound policy configured
☐ IDS/IPS active (not passive)
☐ DDoS mitigation service subscribed
☐ Firewall logs sent to SIEM
☐ Firewall rules reviewed monthly
☐ Blocked traffic alerts configured
☐ Geographic IP blocking implemented
☐ Rate limiting configured
```

---

### Layer 2: NETWORK SEGMENTATION

**Objective:** Isolate critical assets and limit lateral movement

**Network Architecture:**
```
┌─────────────────────────────────────────────────────────────┐
│                    INTERNET                                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
            ┌──────────▼────────────┐
            │  Firewall (Primary)   │
            └──────────┬────────────┘
                       │
        ┌──────────────┼──────────────┐
        │              │              │
    ┌───▼────┐     ┌──▼────┐    ┌────▼───┐
    │ DMZ    │     │ LAN   │    │ Admin  │
    │ (Web)  │     │(Users)│    │ VLAN   │
    └───┬────┘     └──┬────┘    └────┬───┘
        │             │              │
     [Web Server]  [Workstations]  [Admins]
        │             │              │
        └──────┬──────┴──────┬───────┘
               │             │
          ┌────▼─────────────▼────┐
          │  Internal Firewall    │
          │  (VLAN separation)    │
          └────┬──────┬──────┬────┘
               │      │      │
          ┌────▼──┐  ┌▼──┐  ┌▼────────┐
          │Data   │  │IT │  │Critical │
          │Center │  │Ops│  │Systems  │
          └───────┘  └───┘  └─────────┘
```

**Segmentation Rules:**

1. **DMZ (Demilitarized Zone)**
   ```
   Characteristics:
   ├─ Network: 10.0.200.0/24
   ├─ Devices: Web servers, mail servers, DNS
   ├─ Inbound from: Internet (HTTP/HTTPS/DNS only)
   ├─ Inbound from: LAN (ICMP/SSH to manage only)
   └─ Outbound to: Internet (HTTP/HTTPS/DNS), LAN (none by default)
   
   Firewall Rules (DMZ → LAN):
   ├─ DENY web server to LAN database (Block by default)
   ├─ ALLOW app server to DB server (port 3306 only)
   └─ ALLOW web server → DNS (port 53 only)
   
   Purpose:
   └─ If DMZ is compromised, attacker can't reach internal LAN
   ```

2. **User Workstations VLAN**
   ```
   Characteristics:
   ├─ Network: 10.0.10.0/24
   ├─ Devices: Desktops, laptops, printers
   ├─ Connectivity: Limited to required services only
   └─ Admin access: Restricted
   
   Outbound Access Rules:
   ├─ ALLOW: DNS (port 53)
   ├─ ALLOW: HTTP/HTTPS (port 80/443) to approved sites
   ├─ ALLOW: SMTP/IMAP (email)
   ├─ DENY: SMB (port 445) — no lateral movement via file shares
   ├─ DENY: RDP (port 3389)
   └─ DENY: SSH (port 22)
   
   Purpose:
   └─ Workstations isolated from critical systems
      └─ If workstation compromised, attacker can't reach servers
   ```

3. **Administrative VLAN**
   ```
   Characteristics:
   ├─ Network: 10.0.1.0/24
   ├─ Devices: Admin workstations, jump hosts
   ├─ Access: Limited to authorized admins only
   ├─ Monitoring: 100% of activity logged
   └─ MFA: Required for access
   
   Inbound Rules:
   ├─ ALLOW: From admin workstations only (MAC whitelist)
   ├─ ALLOW: RDP/SSH to servers in this VLAN
   ├─ DENY: From user workstations
   └─ DENY: From internet
   
   Outbound Rules:
   ├─ ALLOW: SSH/RDP to production systems
   ├─ ALLOW: DNS
   ├─ DENY: Internet access (except to approved tools)
   └─ DENY: Peer-to-peer with user workstations
   
   Logging:
   ├─ All RDP connections logged (session recording recommended)
   ├─ All commands executed on admin account
   ├─ All file accesses logged
   └─ Admin account login time/location tracked
   ```

4. **Critical Systems VLAN**
   ```
   Characteristics:
   ├─ Network: 10.0.50.0/24
   ├─ Devices: Domain controllers, databases, file servers
   ├─ Access: From admin VLAN only
   ├─ Monitoring: 100% of network traffic monitored
   └─ Connectivity: Heavily restricted
   
   Inbound Rules:
   ├─ ALLOW: SSH/RDP from admin VLAN
   ├─ ALLOW: Backup traffic from backup server
   ├─ DENY: All other traffic
   
   Outbound Rules:
   ├─ ALLOW: DNS to internal DNS only
   ├─ ALLOW: NTP (time sync)
   ├─ DENY: Internet access
   ├─ DENY: Email or web browsing
   └─ DENY: Unnecessary external traffic
   
   Purpose:
   └─ Critical assets protected from compromised workstations
   ```

**VLAN Jumping Detection:**

```
Attack Scenario: Compromised workstation tries to reach DC

Step 1: Attacker on 10.0.10.5 (user VLAN)
Step 2: Creates VLAN tagging packet to access 10.0.50.x (critical VLAN)
Step 3: Firewall detects attempt and blocks

Detection:
├─ Method 1: Firewall sees port-based VLAN hop attempt
├─ Method 2: VLAN boundary IDS detects unusual VLAN traffic
├─ Method 3: User VLAN device appears on critical VLAN
└─ Alert: "Unauthorized VLAN access detected from 10.0.10.5"

Prevention:
├─ Port security: Port doesn't accept VLAN tags from users
├─ BPDU guard: Blocks spanning tree manipulation
├─ Root guard: Prevents rogue switches
└─ Dynamic ARP inspection: Prevents ARP spoofing
```

**Defence in Depth Layer 2 Checklist:**
```
☐ Network segmentation documented in diagram
☐ DMZ separated from internal network
☐ Critical systems isolated in separate VLAN
☐ Admin VLAN exists with restricted access
☐ Inter-VLAN firewall rules configured
☐ Default-deny between VLANs policy
☐ VLAN access logs collected
☐ VLAN hopping attempts logged/alerted
☐ Port security enabled on switches
☐ Rogue switch detection enabled
```

---

### Layer 3: ENDPOINT SECURITY

**Objective:** Protect individual computers and servers from malware and unauthorized access

**Endpoint Protection Stack:**

```
Endpoint Security Layers:

┌─────────────────────────────────────────────┐
│          USER APPLICATION                   │
├─────────────────────────────────────────────┤
│ Layer 3.1: Application Whitelisting        │
│   • Only approved apps can run              │
├─────────────────────────────────────────────┤
│ Layer 3.2: EDR (Endpoint Detection Resp.)  │
│   • Monitor process execution               │
│   • Detect suspicious behavior              │
├─────────────────────────────────────────────┤
│ Layer 3.3: Host Firewall (Windows Firewall)│
│   • Control inbound/outbound per app        │
├─────────────────────────────────────────────┤
│ Layer 3.4: Antivirus / Anti-malware        │
│   • Signature-based detection               │
├─────────────────────────────────────────────┤
│          OPERATING SYSTEM                   │
│  • OS hardening (disable unnecessary svcs) │
├─────────────────────────────────────────────┤
│ Layer 3.5: File Integrity Monitoring       │
│   • Detect unauthorized changes             │
├─────────────────────────────────────────────┤
│ Layer 3.6: UEFI/BIOS Security              │
│   • Secure boot enabled                     │
│   • UEFI firmware password set              │
└─────────────────────────────────────────────┘
```

**Key Controls:**

1. **Application Whitelisting**
   ```
   Purpose: Only approved applications can run
   Implementation: 
   ├─ Tool: AppLocker (Windows) / SELinux (Linux)
   ├─ Rules: Path-based (C:\Program Files\)
   ├─ Rules: Publisher-based (digital signature)
   └─ Rules: Hash-based (known good executables)
   
   Example AppLocker Rule:
   ┌─ Action: Allow
   ├─ Path: C:\Program Files\*\*.exe
   ├─ Scope: All users
   └─ Exception: C:\Program Files\Suspicious\*.exe (Deny)
   
   Whitelist Maintenance:
   ├─ Review new applications monthly
   ├─ Add approved applications to whitelist
   ├─ Remove deprecated applications
   └─ Test on pilot group before production
   
   Alert on:
   ├─ Execution from unauthorized paths (Temp, Downloads)
   ├─ Unsigned executables
   ├─ Scripts running as admin
   └─ Office macros execution
   ```

2. **EDR (Endpoint Detection & Response)**
   ```
   Agent Components:
   ├─ Process monitoring: Parent-child relationships
   ├─ File monitoring: Creation, modification, deletion
   ├─ Network monitoring: Connections, DNS queries
   ├─ Registry monitoring: HKEY modifications
   ├─ Memory scanning: Injected code detection
   └─ Behavioral analysis: Suspicious patterns
   
   Detection Examples:
   ├─ Office → PowerShell (document exploit)
   ├─ Explorer → Cmd (file share enumeration)
   ├─ Services → Temp Exe (malware installation)
   ├─ Calc → Network Connection (unexpected behavior)
   └─ Legitimate app, weird time (off-hours activity)
   
   Response Capabilities:
   ├─ Quarantine suspicious files
   ├─ Kill malicious processes
   ├─ Unload malicious DLLs
   ├─ Block C2 connections
   ├─ Isolate endpoint from network
   └─ Preserve memory/disk for forensics
   
   SOC Integration:
   ├─ EDR alerts to SIEM in real-time
   ├─ Alert prioritization: Critical > High > Medium
   ├─ Automated response for known threats
   └─ SOC tier-2 review for unknown threats
   ```

3. **Host Firewall Configuration**
   ```
   Default Policy:
   ├─ Inbound: Block all (exception for approved services)
   ├─ Outbound: Block all (exception for approved traffic)
   
   Inbound Exceptions:
   ├─ ALLOW: RDP (port 3389) from admin VLAN only
   ├─ ALLOW: SSH (port 22) from admin VLAN only
   ├─ ALLOW: WinRM (port 5985) from admin servers
   ├─ ALLOW: SNMP (port 161) from monitoring server
   └─ DENY: Everything else
   
   Outbound Exceptions:
   ├─ ALLOW: Svchost.exe → DNS (port 53)
   ├─ ALLOW: Edge.exe → HTTPS (port 443)
   ├─ ALLOW: Outlook.exe → SMTP (port 587)
   ├─ DENY: Powershell.exe → Internet
   └─ DENY: Suspicious application → Internet
   
   Per-Application Rules:
   ├─ Calculator: No network access needed (block all)
   ├─ Paint: No network access needed (block all)
   ├─ Notepad: No network access needed (block all)
   ├─ Services.exe: Allow necessary ports only
   └─ System.exe: Allow necessary ports only
   
   Notification:
   ├─ Block notifications: Show to users (security awareness)
   ├─ Users can request approval
   ├─ IT reviews requests (whitelist if legitimate)
   └─ Blocked attempts logged for SIEM
   ```

4. **Antivirus & Anti-malware**
   ```
   Signature-based Detection:
   ├─ Update frequency: 1x daily (at minimum)
   ├─ Cloud integration: Enable cloud file scanning
   ├─ PUP detection: Block potentially unwanted programs
   └─ Exploit protection: Enable exploit guard
   
   Behavioral Detection:
   ├─ Monitor registry modifications
   ├─ Monitor file modifications
   ├─ Monitor network connections
   ├─ Monitor PowerShell execution
   └─ Alert on suspicious patterns
   
   Quarantine Handling:
   ├─ Move infected files to quarantine
   ├─ Log quarantine events
   ├─ Alert SOC on threats
   ├─ Retain samples for forensics
   └─ Report to threat intelligence
   
   Configuration:
   ├─ Full scan schedule: Weekly (low-risk time)
   ├─ Quick scan schedule: Daily
   ├─ Cloud-delivered protection: Enabled
   ├─ Real-time protection: Enabled
   └─ Exclusions: Minimize (only if necessary)
   ```

**Defence in Depth Layer 3 Checklist:**
```
☐ Antivirus deployed to all endpoints
☐ Antivirus definitions updated daily
☐ EDR agent deployed to critical systems
☐ Application whitelisting configured
☐ Host firewall enabled with default-deny
☐ Windows Defender Exploit Guard enabled
☐ Sysmon deployed for process monitoring
☐ File integrity monitoring configured
☐ USB auto-run disabled
☐ Macro execution disabled by default
```

---

### Layer 4: DATA PROTECTION

**Objective:** Protect data at rest and in transit

**Data Classification:**

```
Data Classes by Sensitivity:

PUBLIC:
├─ Information: Published on company website
├─ Loss impact: None
├─ Examples: Marketing materials, public announcements
└─ Protection: No special controls required

INTERNAL:
├─ Information: Shared within organization
├─ Loss impact: Low (internal disclosure)
├─ Examples: Process documentation, meeting notes
└─ Protection: Access control, encryption optional

CONFIDENTIAL:
├─ Information: Restricted to specific teams
├─ Loss impact: High (competitive advantage)
├─ Examples: Business plans, customer lists, financial data
└─ Protection: Access control, encryption required

HIGHLY CONFIDENTIAL:
├─ Information: Restricted to executives/board
├─ Loss impact: Critical (business-threatening)
├─ Examples: Mergers, executive compensation, legal matters
└─ Protection: Access control, encryption mandatory, audit logging
```

**Encryption Strategy:**

1. **Data at Rest (Stored Data)**
   ```
   Encryption Methods:
   ├─ Full Disk Encryption (FDE): BitLocker (Windows), FileVault (Mac)
   ├─ Folder Encryption: Encrypting File System (EFS)
   ├─ File-level: 7-Zip, WinRAR with AES-256
   └─ Database: SQL Server Transparent Data Encryption (TDE)
   
   Implementation:
   ├─ ALL laptops: BitLocker enabled (mandatory)
   ├─ ALL workstations: BitLocker enabled (recommended)
   ├─ ALL servers: BitLocker enabled (critical systems)
   ├─ File servers: Folder encryption for sensitive data
   ├─ Databases: TDE for CONFIDENTIAL and above
   └─ Backups: Encrypted storage at rest
   
   Key Management:
   ├─ BitLocker recovery key stored in Active Directory
   ├─ Database encryption keys backed up separately
   ├─ Keys rotated annually
   ├─ Key escrow for organizational access
   └─ Key destruction upon data retirement
   ```

2. **Data in Transit (Encrypted Communication)**
   ```
   Encryption Methods:
   ├─ TLS 1.2+ for all HTTPS traffic
   ├─ IPSec VPN for site-to-site communication
   ├─ WPA3 for wireless networks
   └─ TLS for email (TLS-required SMTP)
   
   Implementation:
   ├─ Web servers: HTTPS only (no HTTP)
   ├─ Certificate validity: Check monthly
   ├─ Certificate pinning: For critical APIs
   ├─ VPN required: For remote access
   ├─ Email: TLS enforced with external domains
   └─ Wireless: WPA3 (WPA2 minimum if WPA3 unavailable)
   
   Certificate Management:
   ├─ Valid certificates: Minimum 2048-bit RSA
   ├─ Certificate rotation: 30 days before expiry
   ├─ CSR process: Formal approval required
   ├─ Self-signed certs: Prohibited (except internal CA)
   └─ Certificate pinning: Implemented for APIs
   
   Certificate Transparency:
   ├─ Subscribe to CT logs for your domains
   ├─ Alert on unexpected certificate issuance
   ├─ Monitor for domain impersonation attempts
   └─ Example alert: "New cert issued for company.com"
   ```

**DLP (Data Loss Prevention):**

```
Detection Methods:

Method 1: Keyword-based
├─ Search for: "Social Security", "Credit Card", etc.
├─ Example: File contains "SSN: 123-45-6789"
└─ Action: Block or quarantine

Method 2: Fingerprint/Hash-based
├─ Search for: Known confidential documents
├─ Example: MD5 of "Strategic Plan 2026.pdf"
└─ Action: Block copying or sharing

Method 3: Pattern-based
├─ Search for: 9-digit SSN format (xxx-xx-xxxx)
├─ Search for: 16-digit credit card format
└─ Action: Warn or block

Scope:
├─ Email: Scan outbound emails for sensitive data
├─ File shares: Scan for unauthorized access
├─ USB devices: Block copying to removable media
├─ Cloud storage: Prevent upload to personal accounts
└─ Printers: Prevent printing of sensitive documents

Example DLP Policy:

Policy Name: "Credit Card Number Protection"
├─ Condition: File contains pattern \d{4}-\d{4}-\d{4}-\d{4}
├─ Scope: All emails, USB drives, cloud uploads
├─ Action: Block transmission + Alert SOC
└─ Exception: Finance department (allowed with approval)
```

**Defence in Depth Layer 4 Checklist:**
```
☐ Data classification policy documented
☐ Encryption policy for data at rest
☐ Encryption policy for data in transit
☐ BitLocker enabled on all laptops
☐ BitLocker enabled on critical servers
☐ TLS 1.2+ enforced on web servers
☐ VPN required for remote access
☐ DLP tool deployed (Email/USB/Cloud)
☐ Certificate management process documented
☐ Certificate rotation automated
```

---

### Layer 5: ACCESS CONTROL

**Objective:** Ensure only authorized users access resources

**IAM Hierarchy:**

```
AUTHENTICATION (Verify identity)
    ↓
AUTHORIZATION (Verify permissions)
    ↓
ACCOUNTING (Log access)
    ↓
AUDIT (Review logs for violations)
```

**Authentication Controls:**

1. **Multi-Factor Authentication (MFA)**
   ```
   MFA Requirements:
   ├─ Tier 1 (ALL users): MFA for email/VPN access
   ├─ Tier 2 (Admins): MFA for admin portals
   ├─ Tier 3 (Executives): Hardware token (Yubikey/smartcard)
   
   Supported Methods:
   ├─ SMS (acceptable if no better option)
   ├─ Time-based One-Time Password (TOTP): Authenticator app
   ├─ Push notification: Mobile app approval
   ├─ Hardware token: Yubikey, smartcard
   ├─ Windows Hello: Biometric or PIN
   └─ Passwordless: Windows Hello for Business
   
   Enforcement:
   ├─ VPN access: Mandatory MFA (hardware token)
   ├─ Cloud services: Mandatory MFA for admin accounts
   ├─ Email: Mandatory MFA for privileged users
   └─ Critical systems: Mandatory MFA for all access
   
   Backup Codes:
   ├─ Printed and stored securely (safe/vault)
   ├─ Used ONLY if authenticator device lost
   ├─ Must be destroyed after use
   └─ Distribution: One per user, physically handed over
   ```

2. **Password Policy**
   ```
   Requirements:
   ├─ Minimum length: 14 characters
   ├─ Complexity: UPPER + lower + numbers + symbols
   ├─ History: Cannot reuse last 24 passwords
   ├─ Expiration: 90 days (or passwordless enforced)
   ├─ Lockout: 5 failed attempts = 30 min lockout
   └─ No common patterns: Cannot contain username/company name
   
   Passphrase Example:
   ├─ Bad: "Welcome123!" (dictionary word + predictable)
   ├─ Good: "BlueSky$Sunset#2026" (random words + symbols)
   └─ Better: Use passphrase generator or biometric
   
   Deprecated:
   ├─ 90-day mandatory rotation (causes weak passwords)
   └─ Password hints (security theater, not needed)
   
   Password Manager:
   ├─ Enterprise password manager: 1Password, LastPass
   ├─ Admins required to use password manager
   ├─ Centralized password management
   └─ Audit trail of password access
   ```

3. **Privilege Management**
   ```
   Principle of Least Privilege (PoLP):
   ├─ Users: Standard user (no admin)
   ├─ Admins: Admin account separate from user account
   ├─ Just-In-Time (JIT): Temporary privilege elevation
   ├─ Just-Enough-Access (JEA): Minimum necessary permissions
   
   Admin Account Management:
   ├─ Separate accounts: Domain\john (user) vs Domain\john.admin (admin)
   ├─ Workstation restriction: Admin account only on secure admin workstations
   ├─ No email: Admin account cannot access email
   ├─ No internet: Admin account restricted from web browsing
   ├─ Session recording: All admin sessions recorded and logged
   └─ MFA mandatory: All admin account access requires MFA
   
   Service Account Management:
   ├─ Dedicated service accounts: One per critical service
   ├─ Weak privilege: Only necessary permissions granted
   ├─ No interactive logon: Service accounts don't need RDP access
   ├─ Managed Service Accounts (gMSA): Auto-rotating passwords
   └─ Audit all service account usage
   
   Privileged Access Workstation (PAW):
   ├─ Dedicated computer for admin work only
   ├─ No user data on PAW (separate from daily use)
   ├─ Hardened OS: Minimal services, strict firewall
   ├─ Network segmentation: PAW on isolated admin VLAN
   ├─ Multi-factor: Every PAW access requires MFA
   └─ Monitoring: 100% of PAW activity logged
   ```

**Authorization Controls:**

```
RBAC (Role-Based Access Control):

Define Roles:
├─ Domain Admin: Full domain control
├─ Exchange Admin: Email system only
├─ Database Admin: Database systems only
├─ File Share Admin: File server access only
├─ Security Admin: Security tools only
└─ Helpdesk Tier 1: Password resets, basic troubleshooting

Assign Users to Roles:
├─ John: Assigned to "Database Admin" role
├─ Jane: Assigned to "File Share Admin" role
├─ Mike: Assigned to "Security Admin" role

Permissions Automatically Applied:
├─ John: Can create/modify databases, cannot touch file servers
├─ Jane: Can manage file shares, cannot touch databases
├─ Mike: Can configure audit logging, cannot manage servers

Benefits:
├─ Consistent permissions (all DBAs have same access)
├─ Easy to audit (check role membership)
├─ Easy to remove access (remove from role, all permissions revoked)
└─ Scalable (add users to existing roles)
```

**Accounting & Audit:**

```
What to Log:

1. Authentication Logs:
   ├─ Successful logons (Event 4624)
   ├─ Failed logons (Event 4625)
   ├─ Password changes (Event 4723)
   └─ MFA usage (successful/failed)

2. Authorization Logs:
   ├─ Group membership changes (Event 4732)
   ├─ Permission changes (Event 4670)
   ├─ Privilege escalation (Event 4688)
   └─ Admin account usage (Event 4624 with Type 10)

3. Data Access Logs:
   ├─ File access (Event 4656)
   ├─ Database queries (database audit logs)
   ├─ Email access (Exchange audit logs)
   └─ Sensitive data read (DLP logs)

How Long to Retain:
├─ Standard logs: 90 days
├─ Security-critical logs: 1 year
├─ Compliance-required logs: 3-7 years
└─ Backup: Retain indefinitely (offline)

Review Frequency:
├─ Real-time: Critical alerts to SIEM
├─ Daily: SIEM correlation rules
├─ Weekly: Failed login attempts by user
├─ Monthly: Privilege escalation events
├─ Quarterly: User access review (certification)
└─ Annually: Audit trail review by compliance
```

**Defence in Depth Layer 5 Checklist:**
```
☐ MFA enforced for all privileged accounts
☐ Separate admin account policy enforced
☐ PAW (Privileged Access Workstation) deployed
☐ RBAC implemented in Active Directory
☐ Service accounts use managed service accounts (gMSA)
☐ Password policy enforced (14 char, complex)
☐ Account lockout configured (5 attempts, 30 min)
☐ Event logging enabled for 4624, 4625, 4720, 4732
☐ Admin session recording enabled
☐ Quarterly user access certification
```

---

### Layer 6: DETECTION & MONITORING

**Objective:** Detect attacks in progress and respond quickly

**SIEM Integration:**

```
Data Sources:
├─ Windows Event Logs (Sysmon, Security, System)
├─ Firewall logs (connections, blocked traffic)
├─ IDS/IPS alerts (suspicious traffic)
├─ EDR alerts (malware, exploitation attempts)
├─ DNS logs (C2 communication)
├─ Proxy logs (web activity)
├─ Database audit logs (data access)
└─ Application logs (errors, access)

Alert Rules:

Rule 1: Brute Force Detection
├─ Condition: >10 failed logons in 15 minutes (Event 4625)
├─ Target account: svc_admin (service account)
├─ Severity: CRITICAL
├─ Action: Lock account, alert SOC immediately

Rule 2: Privilege Escalation
├─ Condition: Non-admin user added to domain admins
├─ Event ID: 4732 (Group membership modified)
├─ Severity: CRITICAL
├─ Action: Immediate investigation required

Rule 3: Unusual Process Execution
├─ Parent process: WINWORD.EXE (Word)
├─ Child process: powershell.exe (command shell)
├─ Severity: HIGH
├─ Action: Alert, review process command-line

Rule 4: C2 Beaconing
├─ Pattern: Consistent outbound connections every 60 seconds
├─ Destination: Non-business IP
├─ Data size: Consistent (~512 bytes)
├─ Severity: CRITICAL
├─ Action: Block destination, isolate endpoint

Baseline Alerting:
├─ Establish normal baseline (e.g., John logons 9-5 weekdays)
├─ Alert on deviation (e.g., John logons at 3 AM)
├─ Reduce false positives (whitelist known deviations)
└─ Adjust baseline monthly as patterns change
```

**SOC Workflow:**

```
Incident Detection → Triage → Investigation → Response → Recovery

TIER 1 (Automated):
├─ Alert received from SIEM
├─ Automated checks: Is system patched? Is EDR running?
├─ Automated actions: Isolate endpoint if critical alert
└─ Escalate if cannot resolve

TIER 2 (Analyst):
├─ Review alert context
├─ Gather additional data (other alerts for same system)
├─ Check threat intelligence (Is IP known malicious?)
├─ Determine if true positive or false alarm
├─ Escalate to incident response if true positive

TIER 3 (Senior Analyst / IR Team):
├─ Investigate compromise scope (how many systems?)
├─ Determine attack objective
├─ Plan response (contain, eradicate, recover)
├─ Execute containment (isolate systems, block C2)
└─ Document lessons learned
```

**Defence in Depth Layer 6 Checklist:**
```
☐ SIEM deployed (Splunk, LogRhythm, Sentinel)
☐ Firewall logs sent to SIEM
☐ EDR logs sent to SIEM
☐ Windows event logs sent to SIEM
☐ DNS logs sent to SIEM
☐ Alert rules configured for critical events
☐ Alert tuning completed (reducing false positives)
☐ SOC runbooks documented
☐ Escalation procedures defined
☐ On-call rotation established
```

---

### Layer 7: INCIDENT RESPONSE & RECOVERY

**Objective:** Respond to attacks and recover operations

**Incident Response Plan:**

```
PREPARATION:
├─ Incident response team identified
├─ Runbooks written for common scenarios
├─ Forensic tools available and tested
├─ Communication templates prepared
└─ Legal/PR contact information documented

DETECTION & ANALYSIS:
├─ Alert received and triaged
├─ Severity assessed (Critical/High/Medium/Low)
├─ Scope determined (1 endpoint? 100 endpoints?)
├─ Attack vector identified (phishing? exploit? insider?)
└─ Evidence preserved for forensics

CONTAINMENT:
├─ SHORT-TERM: Isolate affected systems (network disconnect)
├─ LONG-TERM: Remove persistence mechanisms
│  ├─ Delete malicious services
│  ├─ Delete malicious scheduled tasks
│  ├─ Remove unauthorized accounts
│  └─ Clean registry of persistence entries
└─ ERADICATION: Remove all malware traces

RECOVERY:
├─ Restore from clean backups (if available)
├─ Rebuild compromised systems from clean media
├─ Re-deploy patches and updates
├─ Verify systems operational and secure
└─ Monitor for signs of re-infection

POST-INCIDENT:
├─ Conduct root cause analysis
├─ Identify control gaps that enabled attack
├─ Implement improvements (new firewall rules, patches, etc.)
├─ Document lessons learned
├─ Update security awareness training
└─ Communicate findings to stakeholders
```

**Backup & Recovery Strategy:**

```
The 3-2-1 Backup Rule:

├─ 3 copies of important data
│  ├─ Original (production system)
│  ├─ Backup copy 1 (primary backup)
│  └─ Backup copy 2 (secondary backup)
├─ 2 different storage media types
│  ├─ Primary: SAN or NAS (fast recovery)
│  └─ Secondary: Tape or S3 (long-term, offline)
└─ 1 copy offsite
   └─ Geographically remote location (disaster recovery)

Backup Frequency:
├─ Database: Hourly incremental, daily full
├─ File servers: Daily incremental, weekly full
├─ Critical systems: 4-hour RPO (Recovery Point Objective)
└─ User data: Daily backup

Immutability:
├─ Backups must not be deletable by users or even admins
├─ Ransomware cannot encrypt backups
├─ Azure Backup: Immutable retention period set
├─ AWS S3: Object Lock enabled (WORM - Write Once, Read Many)
└─ On-prem: Air-gapped backup system (no network access)

Recovery Time Objective (RTO):
├─ Critical systems: 1 hour (redundancy required)
├─ Business-essential: 4 hours
├─ Standard systems: 1 day
└─ Non-critical: 1 week

Test Plan:
├─ Test restore: Quarterly
├─ Test full disaster recovery: Annually
├─ Test partial recovery: Monthly (different systems)
└─ Document time taken (measure against RTO)
```

**Forensics & Investigation:**

```
Preserve Evidence:

Do NOT:
├─ Power off system immediately (loses volatile memory)
├─ Reboot system (clears memory and logs)
├─ Run antivirus scans (modifies malware)
├─ Delete temporary files (may contain evidence)

DO:
├─ Connect network isolation device (prevents C2 communication)
├─ Capture volatile memory (RAM) to external drive
├─ Create forensic image of entire disk (bit-perfect copy)
├─ Document chain of custody (who handled evidence)
└─ Seal and label evidence for laboratory analysis

Forensic Analysis:

1. Memory Analysis (Volatility):
   ├─ Find injected code (hidden processes)
   ├─ Find network connections at time of compromise
   ├─ Find API hooks (malware detection evasion)
   └─ Find encryption keys (for ransomware decryption)

2. Disk Analysis (EnCase, FTK):
   ├─ Find deleted files (from malware, attackers)
   ├─ Timeline analysis (what happened in what order)
   ├─ Registry analysis (malware persistence locations)
   └─ Artifact analysis (browser history, recent files, etc.)

3. Log Analysis:
   ├─ Event log review (user logons, privilege escalation)
   ├─ Firewall log review (network connections)
   ├─ Application log review (unusual activity)
   └─ Web server log review (exploitation attempts)
```

**Defence in Depth Layer 7 Checklist:**
```
☐ Incident response plan documented
☐ IR team identified and trained
☐ Incident response playbooks written
☐ Escalation procedures defined
☐ Communication templates prepared
☐ Forensic tools available (Volatility, EnCase, FTK)
☐ Chain of custody procedures documented
☐ Backup strategy documented (3-2-1 rule)
☐ Backup immutability enforced
☐ RTO/RPO defined for critical systems
☐ Backup restoration tested quarterly
☐ Disaster recovery plan tested annually
```

---

## Implementation Priority Matrix

| Control | Layer | Impact | Effort | Priority | Timeline |
|---------|-------|--------|--------|----------|----------|
| Firewall rules | 1 | High | Low | CRITICAL | Week 1 |
| Network segmentation | 2 | High | Medium | CRITICAL | Month 1-2 |
| EDR deployment | 3 | High | Medium | CRITICAL | Month 1 |
| MFA implementation | 5 | High | Medium | CRITICAL | Month 1-2 |
| SIEM deployment | 6 | High | High | CRITICAL | Month 2-3 |
| Backup testing | 7 | High | Low | CRITICAL | Ongoing |
| Application whitelisting | 3 | Medium | High | HIGH | Month 3-4 |
| DLP implementation | 4 | Medium | High | HIGH | Month 3 |
| Privilege audit | 5 | Medium | Medium | HIGH | Month 2 |
| Incident response plan | 7 | Medium | Low | HIGH | Month 1 |

---

## Metrics & KPIs

```
Layer 1 Metrics:
├─ % traffic blocked by firewall: Should be >90%
├─ DDoS incidents: Should be 0 (or <1 per quarter)
└─ Firewall rule review frequency: Monthly

Layer 2 Metrics:
├─ VLAN hopping attempts: Should be 0
├─ Inter-VLAN unauthorized traffic: Should be 0
└─ Segmentation policy violations: Should be <1 per quarter

Layer 3 Metrics:
├─ % endpoints with EDR: Should be 100%
├─ % systems with application whitelisting: Target 80%
├─ Malware detections: Trend should be declining
└─ EDR detection-to-isolation time: <5 minutes

Layer 4 Metrics:
├─ % systems with FDE: Should be 100%
├─ % data encrypted in transit: Should be 100%
├─ DLP policy violations: Should trend downward
└─ Encryption certificate renewal: 100% before expiry

Layer 5 Metrics:
├─ % accounts with MFA: Admin=100%, Users=90%+
├─ Failed login attempts: Should be <5 per user per month
├─ Privileged account abuse: Should be 0
└─ User access review completion: 100% quarterly

Layer 6 Metrics:
├─ Mean Time to Detect (MTTD): <1 hour for critical alerts
├─ Alert false positive rate: <5%
├─ SIEM data latency: <5 minutes
└─ Alert response time: <15 minutes

Layer 7 Metrics:
├─ Backup success rate: 100%
├─ Backup restoration test: Quarterly, 100% success
├─ RTO actual vs. target: 100% within target
├─ RPO actual vs. target: 100% within target
└─ Incident response time: <1 hour for critical incidents
```

---

## Conclusion

Defence in Depth provides layered protection so that a single failure doesn't lead to complete compromise. Implementing all seven layers ensures:

1. **Resilience:** Multiple detection opportunities
2. **Coverage:** Both external and internal threats
3. **Containment:** Lateral movement prevented
4. **Recovery:** Business continuity protected

Regular review and updates ensure the defence strategy remains effective against evolving threats.

---

*Version History:*
- v2.2 (2026-02-19): Added practical SIEM queries and metrics
- v2.1 (2026-01-15): Expanded detection methods
- v2.0 (2025-12-01): Complete rewrite with seven layers
- v1.0 (2025-10-15): Initial framework
