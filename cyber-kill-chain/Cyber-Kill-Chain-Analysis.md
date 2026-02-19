# Cyber Kill Chain Analysis & Defense Mapping

**Version:** 2.1  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## Overview

The Cyber Kill Chain is a military-inspired framework developed by Lockheed Martin that describes the stages of a cyber attack. Understanding each phase enables defenders to break the chain at any point, making attacks more difficult and costly for adversaries.

---

## The Seven Stages of the Cyber Kill Chain

### 1. RECONNAISSANCE

**Objective:** Gather information about target systems, networks, and personnel.

**Attacker Activities:**
- Network scanning and mapping
- WHOIS, DNS, and OSINT queries
- Social engineering (phone calls, LinkedIn profiling)
- Website analysis (technologies, employees, email patterns)
- Infrastructure discovery (public IP ranges, domains)
- Vulnerability database research

**Real-World Example - APT28 (Fancy Bear):**
```
Timeline: 3-4 weeks before attack
Activities:
├─ Google dorking for exposed documents
├─ LinkedIn enumeration: HR, finance, IT staff profiles
├─ Company website technology stack analysis (ASP.NET version)
├─ Passive DNS lookups for mail servers, VPNs
├─ Whois registration info for admin contacts
└─ Port scanning on public-facing IPs (22, 80, 443, 3389)

Observables Found in Logs:
- Unique User-Agents from single IP scanning multiple domains
- Rapid DNS queries for subdomains (*.company.com)
- Consistent whois-client requests from foreign IP ranges
- SSL certificate database queries
```

**Detection Methods (SOC Level 1):**

| Detection Type | Source | Indicator |
|---|---|---|
| Passive DNS | DNS logs | Multiple failed subdomains in single session |
| Web server logs | IIS/Apache | Unusual bot User-Agents, directory fuzzing |
| Firewall logs | Perimeter FW | Port scans (SYN to closed ports) |
| OSINT tools | External | Leaked credentials in breach databases |

**Defense Strategies:**
```
1. INFORMATION MINIMIZATION
   - Disable directory listing (web servers)
   - Remove metadata from documents
   - Limit employee info in directory
   - Use privacy-protected WHOIS
   - Disable NetBIOS enumeration

2. EXTERNAL MONITORING
   - Certificate Transparency logging
   - Brand monitoring (Google Alerts)
   - Credential leak monitoring (Have I Been Pwned API)
   - Darknet monitoring services
   - Third-party breach notifications

3. NETWORK HARDENING
   - No ICMP replies (ping disabled)
   - Firewall: Only required ports open
   - Rate-limit DNS responses
   - Block Shodan/Censys User-Agents
   - VPN for remote access (no RDP exposed)
```

**Kill Chain Breaker Checklist:**
```
☐ All external documents checked for metadata
☐ Employee directory not searchable externally
☐ WHOIS privacy enabled
☐ SSL certificates monitored for unauthorized issuance
☐ DNS queries logged and monitored
☐ Passive reconnaissance attempts detected
☐ Third-party risk assessments current
```

---

### 2. WEAPONIZATION

**Objective:** Develop malware, exploits, or attack tools customized for the target.

**Attacker Activities:**
- Custom malware development or modification
- Exploit kit configuration
- Phishing email crafting
- Command & control infrastructure setup
- Encryption of payloads
- Polymorph obfuscation (changing malware signatures)

**Real-World Example - Office Zero-Day Exploitation:**
```
Weaponization Process:

Day 1: Exploit Research
├─ CVE-2021-40444 discovered (remote code execution in Office)
├─ PoC code published on GitHub
├─ Attacker downloads and analyzes code
├─ Tests against Office version used by target (Office 2019)
└─ Creates weaponized Word document with embedded HTML/iframe

Day 2: Malware Development
├─ Obtains Cobalt Strike license ($2,000 USD)
├─ Configures C2 server (185.220.101.45:443)
├─ Generates beacon DLL (obfuscated with Mimikatz)
├─ Creates dropper executable (packed with UPX)
└─ Polymorph transformation: changes every 6 hours

Day 3: Phishing Package Assembly
├─ Weaponized document (exploit.docx)
├─ Legitimate-looking subject line targeting finance team
├─ Attachment appears to be "Q4_Budget_Review.docx"
├─ Email body references recent company announcement
└─ Sender spoofed as VP of Finance
```

**Artifacts Left Behind:**

| Artifact | Location | Detection Method |
|----------|----------|------------------|
| C2 infrastructure | WHOIS, SSL certs | Certificate transparency logs |
| Malware samples | VirusTotal | Hash signatures (MD5, SHA256) |
| Exploit code | GitHub, exploit databases | Repository monitoring |
| Domain registration | Domain registrar | Newly registered domains (NRD) |
| Infrastructure | ASN records | BGP hijacking patterns |

**Detection Methods (SOC Level 1):**

```
Weaponization indicators are typically NOT visible at the network edge.
Most detection happens at delivery/execution phases.

However:
- Monitor for purchase of exploit kits (Dark web monitoring)
- Analyze phishing samples for weaponization
- Track malware author profiles (OSINT)
- Monitor legitimate services misused (GitHub, DigitalOcean for C2)
```

**Defense Strategies:**
```
1. ATTACK SURFACE REDUCTION
   - Disable macros in Office (Enterprise mode)
   - Disable automatic file opening
   - Require user interaction for downloads
   - Whitelist approved applications
   - Reduce supported file types

2. EARLY DETECTION
   - Email sandboxing (dynamic analysis)
   - Document analysis for embedded objects
   - Metadata inspection
   - Behavior-based scanning

3. THREAT INTELLIGENCE
   - Subscribe to 0-day monitoring
   - Track vulnerability disclosure timelines
   - Monitor for weaponized exploits
   - Share samples with incident response team
```

**Kill Chain Breaker Checklist:**
```
☐ Exploit patching within 7 days of critical release
☐ Email sandboxing for unknown attachments
☐ Macro execution blocked for untrusted documents
☐ Threat intelligence feeds configured
☐ Malware analysis sandbox available (VirusTotal, Falcon, etc.)
☐ Phishing training current (security awareness)
```

---

### 3. DELIVERY

**Objective:** Get the weaponized payload to the target user/system.

**Attacker Activities:**
- Phishing email campaigns
- Watering hole attacks (compromised legitimate websites)
- Supply chain compromise
- Physical media distribution (USB drops)
- Drive-by downloads
- Spear phishing (highly targeted)

**Real-World Example - APT41 Phishing Campaign:**
```
Target: Manufacturing company (Supply Chain Attack Context)

Delivery Method: Email Phishing
├─ 850 emails sent to engineering team
├─ From: procurement@supplier-company.com (spoofed)
├─ Subject: "RFQ 2026-Q1 - Urgent Response Needed"
├─ Attachment: "RFQ_2026-Availability.docx" (malicious)
├─ Body: References recent project from real supplier
└─ Sent: Tuesday 9:00 AM (high email volume time)

Open Rate Analysis:
├─ 187 emails opened (22% - below average, weak phishing)
├─ 67 attachments downloaded (8% - targeting low risk users)
├─ 23 macros enabled (2.7% - OLD Office versions)
├─ 12 infection attempts (1.4% - compromise threshold)
└─ 5 successful compromises (0.6% - enough for attacker)
```

**Detection Methods (SOC Level 1):**

| Detection Point | Technology | Indicator |
|---|---|---|
| Gateway | Email filter | Malicious attachment hash |
| Sandbox | Cuckoo/Detonator | File behavior analysis |
| Endpoint | EDR (Carbon Black) | Process execution post-download |
| User | Email client | Suspicious sender, poor grammar |
| Network | IDS/IPS | Download from malicious server |

**Email Forensics - What To Check:**

```bash
# Email headers analysis
grep -i "x-originating-ip" suspicious_email.eml
# Check actual IP vs sender domain (spoofing indicator)

grep -i "received" suspicious_email.eml
# Follow chain of mail servers (may reveal real origin)

grep -i "dkim-signature" suspicious_email.eml
# Missing DKIM = spoofing likely

# Content analysis
strings suspicious_email.eml | grep "script"
# Embedded scripts indicate weaponization
```

**Defense Strategies:**
```
1. EMAIL SECURITY
   - DKIM, DMARC, SPF implementation (sender verification)
   - External email warnings (⚠️ [EXTERNAL])
   - Attachment sandboxing (dynamic analysis)
   - Macro blocking for external emails
   - URL rewriting (for click tracking/analysis)

2. USER TRAINING
   - Phishing simulations (quarterly)
   - Suspicious indicator identification
   - Reporting procedures (easy click-to-report)
   - Brand impersonation training
   - Cultural/social engineering awareness

3. TECHNICAL CONTROLS
   - URL filtering (category-based: known malware sites)
   - File type restrictions (prevent .exe, .scr, .vbs)
   - Zip/RAR password protection blocked (doubles extraction)
   - Execution disabled from Downloads folder
   - USB auto-run disabled

4. DETECTION & RESPONSE
   - Alert on: Unusual from: addresses, spoofed domains
   - Alert on: Macro-enabled Office docs from external
   - Alert on: Attachment hash matches known malware
   - Immediate: Disable user account if compromised
   - Cleanup: Remove malicious emails from all users
```

**Real-World Email Analysis Example:**

```
FROM: procurement@top-supplier.com (SPOOFED - real domain is top-supplier.org)
TO: John.smith@targetco.com
SUBJECT: Urgent - RFQ Clarification Needed - Action Required Today

DKIM: ✗ FAIL (missing signature - spoofed)
DMARC: ✗ FAIL (not in DMARC policy)
SPF: ✗ FAIL (IP 185.220.101.55 not authorized)
DOMAIN: top-supplier.com (registered 3 days ago - BRAND NEW)

BODY:
"John,

Quick question on your Q1 bid for widget components.
Can you confirm lead times in attached spreadsheet?

We need to finalize by end of week.

Thanks,
[Actual signature: Jane Smith]"

ATTACHMENT: "Q1-Bid-Spreadsheet.xlsx"
├─ File hash: a1b2c3d4e5f6g7h8 (NOT in enterprise hash whitelist)
├─ Scanned: 0/60 engines detect as malware (obfuscated)
├─ Content: Looks like Excel spreadsheet
└─ Real behavior: Drops Emotet banking trojan

VERDICT: Highly targeted spear phishing
CONFIDENCE: 95% malicious
ACTION: Block, delete, notify user, add to watchlist
```

**Kill Chain Breaker Checklist:**
```
☐ Email gateway configured (SPF/DKIM/DMARC)
☐ URL filtering active (malware sites blocked)
☐ Phishing simulation quarterly (>80% reporting rate)
☐ Attachment sandboxing enabled
☐ External email warnings visible to users
☐ Macro execution disabled by default
☐ Email retention for forensics (90 days min)
☐ Sender verification procedures documented
```

---

### 4. EXPLOITATION

**Objective:** Execute code on target system to establish foothold.

**Attacker Activities:**
- Trigger vulnerability in software
- Run exploit code
- Bypass security controls (UAC, DEP, ASLR)
- Escalate privileges
- Establish initial access

**Real-World Example - Zerologon (CVE-2020-1472) Exploitation:**

```
Vulnerability: Netlogon authentication bypass
Affected: Windows Server 2012-2019, domain controllers
CVSS Score: 10.0 (CRITICAL)

Attack Timeline:

T+0 (09:34 UTC): First exploitation attempt
├─ Attacker sends malformed Netlogon RPC packets
├─ DC accepts empty password for machine account
├─ Attacker obtains DC machine credentials
└─ EDR Alert: "Unusual RPC traffic to Domain Controller"

T+2 minutes (09:36 UTC): Exploitation succeeds
├─ Machine account password reset
├─ Attacker authenticates as DC
├─ Domain Trusts enumeration begins
└─ Privilege escalation complete

T+4 minutes (09:38 UTC): Post-exploitation activities
├─ LDAP queries for domain admins
├─ Active Directory replication (DCSync attack)
├─ Golden Ticket generation (Kerberos forgery)
└─ Ransomware payload staging

Detection Failure:
├─ 0/15 EDR systems detected lateral movement
├─ IDS set to PASSIVE mode (not blocking)
├─ LDAP logs not collected (SIEM gap)
└─ RPC logging not configured
```

**Exploitation Observables:**

| Phase | Observable | Detection Source |
|-------|-----------|------------------|
| Initial exploit | Shellcode in memory | EDR (process memory scan) |
| Code execution | Unusual parent-child process | Sysmon Event 1 |
| Privilege escalation | Token impersonation | EDR behavioral analysis |
| System access | New admin account created | Windows Event 4720 |
| Persistence mechanism | Registry modification | Sysmon Event 12-13 |

**Common Exploitation Techniques & Detection:**

```
TECHNIQUE 1: Macro-enabled Office document
└─ Detection: Word.exe → powershell.exe → cmd.exe → rundll32.exe
   Source: Sysmon Event 1 (Process Creation)
   Alert: Office application spawning shells or system tools

TECHNIQUE 2: Living off the land (LOLBins)
├─ regsvcs.exe: .NET assembly execution
├─ msbuild.exe: XML project file execution
├─ certutil.exe: Encode/decode for obfuscation
├─ rundll32.exe: DLL execution bypass
└─ Detection: Sysmon Event 1, parent-child relationships unusual

TECHNIQUE 3: Privilege escalation via Service
├─ Create service pointing to malicious binary
├─ Service runs as SYSTEM on reboot
├─ Detection: Sysmon Event 13 (Registry modification)
   └─ HKLM\System\CurrentControlSet\Services\*

TECHNIQUE 4: Unquoted Service Path
├─ Service path: C:\Program Files\My App\service.exe
├─ Service loads: C:\Program.exe (attacker-controlled)
├─ Detection: File creation in privileged directories
└─ Source: Windows Defender, Sysmon Event 11

TECHNIQUE 5: DLL Hijacking
├─ Place malicious DLL in application directory
├─ Legitimate app loads attacker's DLL first
├─ Detection: Sysmon Event 7 (Image Load)
   └─ Unusual DLL load paths for known applications
```

**Detection Methods (SOC Level 1):**

```
Sysmon Log Analysis Example:

Event ID: 1 (Process Creation)
ParentImage: C:\Program Files\Microsoft Office\Office16\WINWORD.EXE
Image: C:\Windows\System32\powershell.exe
CommandLine: powershell.exe -nop -w hidden -enc JABzAD0...
User: TARGETCO\john.smith
LogonGuid: {12345678-90ab-cdef-1234-567890abcdef}
TerminalSessionId: 1
ParentProcessId: 4328
ProcessId: 5920

ANALYSIS:
✓ Suspicious: Office parent process running PowerShell
✓ Suspicious: Encoded command line (-enc)
✓ Suspicious: Hidden window (-w hidden)
✓ Normal: User context (not SYSTEM, expected)
✓ Action: ALERT IMMEDIATE, isolate endpoint
```

**Kill Chain Breaker Checklist:**
```
☐ System patching current (monthly windows updates)
☐ Critical vulnerabilities patched within 7 days
☐ UAC enabled on all workstations
☐ ASLR/DEP enabled (compiler & OS settings)
☐ Code Integrity Guard enabled (CIG)
☐ Exploit protection configured
☐ Attack Surface Reduction (ASR) rules enabled
☐ Process execution logging enabled (Sysmon)
☐ EDR agent running on all endpoints
☐ EDR alerts configured for known exploitation techniques
```

---

### 5. INSTALLATION

**Objective:** Establish persistent access to target system.

**Attacker Activities:**
- Install backdoors or remote access tools
- Create new accounts
- Modify system registry
- Plant rootkits
- Establish C2 communication

**Real-World Example - Emotet Banking Trojan Installation:**

```
Installation Timeline (Post-Exploitation):

T+0 (10:15 UTC): Initial malware execution
├─ powershell.exe downloads Emotet payload
└─ Parent: svchost.exe (spoofed process)

T+5 sec (10:15:05): First-stage loader executes
├─ Payload: C:\Users\john.smith\AppData\Local\Temp\~tmp1234.exe
├─ Behavior: Injects code into explorer.exe (Process Injection)
├─ Technique: CreateRemoteThread API
└─ Detection: Should trigger EDR behavioral alert

T+10 sec (10:15:10): Process Injection - explorer.exe
├─ explorer.exe now contains Emotet DLL in memory
├─ explorer.exe opens network socket to C2
├─ Destination: 203.0.113.55:8080
└─ Port 8080 not typical for explorer (anomalous)

T+30 sec (10:15:30): Persistence - Windows Service Creation
├─ Service name: "Windows Update Service" (WUS)
├─ Binary path: C:\Windows\Temp\service.exe
├─ Start type: AUTO_START
├─ Account: LocalSystem
└─ Purpose: Ensure malware survives reboot

T+45 sec (10:15:45): Persistence - Registry Run Key
├─ Registry path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
├─ Value name: "Windows Security Update"
├─ Data: "C:\Windows\Temp\rundll.exe C:\Windows\Temp\emotet.dll,DllMain"
└─ Purpose: Backup persistence if service fails

T+60 sec (10:16:00): Persistence - Scheduled Task
├─ Task name: "Windows Maintenance"
├─ Trigger: Logon event + System startup
├─ Action: C:\Windows\Temp\service.exe
└─ Purpose: Triple redundancy for persistence

T+90 sec (10:16:30): C2 Beacon Registration
├─ First beacon to C2 server
├─ Payload: System info (OS, IP, hostname, user)
├─ Response: Configuration data (C2 URL list, targets)
└─ Frequency: Every 60 seconds ± random jitter
```

**Persistence Mechanisms Detection:**

| Persistence Method | Registry Location | Sysmon Event |
|---|---|---|
| Run key | HKCU\...\Run | Event 13 (Registry set) |
| Service | HKLM\System\Services | Event 13 + Event 1 at startup |
| Scheduled task | C:\Windows\System32\tasks | Event 11 (File create) |
| Startup folder | C:\Users\*\AppData\Roaming\...\Startup | Event 11 |
| Winsock Provider | HKLM\System\CurrentControlSet\Services\Winsock2 | Event 13 |
| AppInit_DLL | HKLM\Software\Microsoft\Windows NT\...AppInit_DLLs | Event 13 |
| COM Hijacking | HKCU\Software\Classes\CLSID | Event 13 |

**Installation Artifacts to Hunt:**

```
1. SUSPICIOUS FILES
   Location patterns:
   ├─ C:\Windows\Temp\* (predictable, often writable)
   ├─ C:\Users\*\AppData\Local\Temp\*
   ├─ C:\ProgramData\*
   └─ C:\Users\*\AppData\Roaming\*
   
   Hunting query (PowerShell):
   Get-ChildItem C:\Windows\Temp -File -Newer (Get-Date).AddHours(-24) | 
     Where {$_.Extension -in @('.exe', '.dll', '.scr')}

2. NEW SERVICES
   Suspicious characteristics:
   ├─ Recently created (compare with OS install date)
   ├─ Binary path in Temp/AppData directories
   ├─ DisplayName doesn't match actual binary
   └─ Runs as LocalSystem or Network Service
   
   Hunting query:
   Get-Service | Where {$_.Status -eq 'Running'} | 
     Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\$($_.Name)" |
     Where {$_.ImagePath -like "*temp*"}

3. REGISTRY MODIFICATIONS
   Check these hives frequently:
   ├─ HKCU\Software\Microsoft\Windows\CurrentVersion\Run
   ├─ HKLM\Software\Microsoft\Windows\CurrentVersion\Run
   ├─ HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
   ├─ HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
   └─ Services registry path
   
   Red flags:
   ├─ Unusual characters in value names
   ├─ Binary paths with spaces, no quotes
   ├─ Recently modified (check LastWriteTime)
   └─ Legitimate service names with wrong paths
```

**Kill Chain Breaker Checklist:**
```
☐ Sysmon installed on all endpoints
☐ Sysmon event 13 (registry) logged to SIEM
☐ Sysmon event 1 (process) with parent-child relationships
☐ Process execution policy enforced
☐ Temp directory permissions restricted (read/write only for owner)
☐ System32 permissions locked down
☐ File integrity monitoring on critical directories
☐ Registry monitoring for Run keys
☐ Scheduled task auditing enabled
☐ Service creation alerts configured in SIEM
☐ EDR agent monitors process injection attempts
```

---

### 6. COMMAND & CONTROL (C2)

**Objective:** Maintain persistent remote access and issue commands.

**Attacker Activities:**
- Establish encrypted communication channel
- Maintain persistent connection
- Issue commands to malware
- Exfiltrate data
- Avoid detection through obfuscation

**Real-World Example - Cobalt Strike C2 Analysis:**

```
C2 Infrastructure Overview:

┌─────────────────────────────────┐
│  Attacker's Cobalt Strike Team  │
│  (attacker-controlled.xyz)      │
└──────────────┬──────────────────┘
               │ (Operator commands)
               ▼
┌─────────────────────────────────┐
│   C2 Server (185.220.101.45)    │
│   • Beacon configuration        │
│   • Compromised host list       │
│   • Task delivery               │
│   • Data exfiltration receiver  │
└──────────────┬──────────────────┘
               │ (HTTPS port 443)
               ▼
┌─────────────────────────────────┐
│  Infected endpoints (Beacons)   │
│  • Finance server (10.0.50.15)  │
│  • HR workstation (10.0.20.33)  │
│  • Domain controller (10.0.1.5) │
└─────────────────────────────────┘

C2 Traffic Pattern:

Beacon Checkin:
Time: Every 60 seconds ± 10s (jitter)
Size: 512-1024 bytes
Direction: Outbound only
Protocol: HTTPS (TLS 1.2)
JA3 fingerprint: Cobalt Strike signature

Encrypted payload structure:
┌─────────────┬────────────┬─────────┐
│ TLS wrapper │ AES key    │ Command │
│ (standard)  │ (encrypted)│ (task)  │
└─────────────┴────────────┴─────────┘

Sample beaconing schedule:
09:00:00 - Initial beacon (new compromise)
09:01:00 - Sleep 60s
09:02:00 - Operator checks new host
09:02:15 - Command sent: "execute ipconfig"
09:02:15 - Beacon wakes, executes command
09:02:30 - Beacon returns with output
09:03:00 - Resume normal 60s interval
```

**Detection Methods - Zeek IDS Analysis:**

```yaml
# Sample Zeek log analysis
conn.log entries for C2 traffic:

ts        | src_ip      | dst_port | service | duration | orig_bytes | resp_bytes
09:00:15  | 10.0.50.15  | 443      | ssl     | 45.231   | 512        | 1024
09:01:15  | 10.0.50.15  | 443      | ssl     | 42.891   | 512        | 1024
09:02:15  | 10.0.50.15  | 443      | ssl     | 48.123   | 512        | 1024
...

ssl.log entries:

server_name: cdn.microsoft.com (SPOOFED SNI!)
server_cert_name: cdn.microsoft.com
issuer: Let's Encrypt
ja3: "772,49195,49199,52393,52392,49196,49200,49162,49161,52394,49171,49172,21,20,..." 
ja3s: "771,49195,0,..." (Cobalt Strike signature!)
validation_status: ok (legitimate cert, but SPOOFED SNI)

RED FLAGS:
✗ Consistent 60-second callback interval
✗ Same data size every callback (not normal)
✗ JA3 fingerprint matches known C2
✗ SNI (Server Name Indication) doesn't match destination IP
✗ Certificate valid but mismatches domain in connection
✗ Outbound to non-business IP during work hours
```

**Hunting for C2 Communication:**

```sql
-- Splunk SPL query to find beaconing patterns
index=network sourcetype=zeek_conn 
  dest_ip NOT IN (whitelist_ips) 
  dest_port=443 
  protocol=tcp 
  | stats 
    count as conn_count, 
    avg(duration) as avg_duration,
    avg(orig_bytes) as avg_sent,
    avg(resp_bytes) as avg_received,
    latest(src_ip) as source
    by dest_ip, dest_port 
  | where 
    avg_duration > 30 AND avg_duration < 60 AND 
    avg_sent > 400 AND avg_sent < 700 AND
    conn_count > 50
  | sort - conn_count

-- Results interpretation:
-- Regular beaconing will show:
-- ✓ Consistent duration (±5 seconds around 45s)
-- ✓ Consistent data sizes (±200 bytes)
-- ✓ High connection count (50+ per hour)
-- ✓ Only a few destination IPs
```

**C2 Domain Indicators:**

| Indicator Type | Example | Detection |
|---|---|---|
| Newly registered domain | cs-payload.top (registered 3 days ago) | WHOIS age <30 days |
| Fast flux DNS | IPs change every 30 minutes | DNS query frequency spikes |
| Suspicious TLD | .xyz, .tk, .ml (free registrars) | Domain reputation check |
| Encrypted DNS (DoH) | cloudflare-dns.com (spoofed) | DNS tunnel detection |
| Cobalt Strike malleable C2 | cdn.microsoft.com (spoofed) | JA3 fingerprint matching |

**Kill Chain Breaker Checklist:**
```
☐ Network egress filtering (allow only necessary traffic)
☐ DNS sinkholing for known C2 domains
☐ SSL inspection for HTTPS traffic (detect spoofed SNI)
☐ IDS/IPS rules for known C2 signatures (JA3 hashes)
☐ Threat intelligence feeds for C2 domains/IPs
☐ Network anomaly detection (beaconing patterns)
☐ NetFlow/sFlow collection for all egress
☐ DNS query logging and monitoring
☐ Endpoint DNS resolution blocking (localhost override)
☐ EDR monitoring for network communication
☐ Block outbound to non-whitelisted IPs/domains
```

---

### 7. ACTIONS ON OBJECTIVE

**Objective:** Achieve the attacker's goal (data theft, disruption, espionage).

**Attacker Activities:**
- Data exfiltration (theft)
- System disruption (ransomware deployment)
- Lateral movement
- Privilege escalation
- Credential harvesting
- Destruction of evidence

**Real-World Example - Ransomware Deployment (Conti Gang):**

```
Attack Timeline (Days 1-15):

DAYS 1-3: Initial Access → C2 Connection
├─ Phishing email deployed to 500 employees
├─ User clicks link, downloads maldoc
├─ Emotet loader executes, C2 beacon established
├─ Attacker gains foothold on 5 systems
└─ Lateral movement planning begins

DAYS 4-7: Reconnaissance & Lateral Movement
├─ Attacker enumeration:
│  ├─ Domain enumeration (net group "domain admins")
│  ├─ File share discovery (net view \\computer)
│  ├─ User enumeration (net user /domain)
│  └─ Group Policy enumeration (gpresult /h)
├─ Lateral movement:
│  ├─ Admin share exploitation (\\server\C$)
│  ├─ SMB vulnerability (CVE-2020-0796)
│  └─ RDP brute force (weak service account passwords)
└─ Privilege escalation: SeImpersonate token abuse

DAYS 8-12: Persistence & Reconnaissance
├─ Persistence mechanisms:
│  ├─ Golden Ticket generation (Kerberos forged admin ticket)
│  ├─ Skeleton Key malware (HKLM registry mod for backdoor)
│  ├─ DSRM password change (Directory Services Restore Mode)
│  └─ New admin account creation: "svc_system"
├─ Extensive recon:
│  ├─ Backup system locations identified
│  ├─ Business-critical data folders mapped
│  ├─ Backup schedule learned (best time to encrypt)
│  └─ Domain admin credentials harvested

DAYS 13-14: Pre-Encryption Activity
├─ Disabling security:
│  ├─ Windows Defender disabled (Set-MpPreference)
│  ├─ Windows Firewall disabled
│  ├─ SIEM agent disabled/uninstalled
│  └─ Antivirus software removed
├─ Backup destruction:
│  ├─ Identified backup servers
│  ├─ Mounted backup shares
│  ├─ Deleted backup snapshots
│  └─ Deleted recovery points (wmic shadowcopy delete)
└─ Final payload staging:
   ├─ Conti ransomware binary uploaded to multiple servers
   └─ PsExec/WMIC execution commands prepared

DAY 15: Ransomware Detonation (11:47 PM Friday)
├─ Timing: End of business Friday (fewer IT staff)
├─ Execution method: PsExec to 40+ systems simultaneously
│  Command: psexec.exe \\* -u domain\svc_system -p Password123 
│           C:\Windows\Temp\conti.exe
├─ Encryption starts:
│  ├─ File enumeration: All drives, all file types
│  ├─ Encryption: AES-256 + RSA-2048 hybrid
│  ├─ File extension: .CONTI added
│  └─ Speed: 2-5 files/second per system
└─ Ransom note displayed: 
   "Your data is encrypted. Pay $250,000 in Bitcoin for decryption key"

IMPACT:
├─ 87% of enterprise files encrypted in 6 hours
├─ Backup systems destroyed (no recovery option)
├─ Business halted (unable to access critical data)
├─ $250,000 ransom demand
└─ Estimated recovery time: 3-6 months
```

**Detection Failures - Why This Wasn't Caught:**

```
DETECTION GAP #1: Reconnaissance phase (Days 4-7)
├─ Command execution not monitored
├─ net.exe commands not audited
├─ AD queries not logged
└─ Lateral movement via SMB not inspected
└─ Result: Attacker gained domain admin privileges undetected

DETECTION GAP #2: Persistence creation (Days 8-12)
├─ Golden Ticket creation not detected
├─ Registry modifications not alerted
├─ New admin account creation logged but not correlated
├─ DSRM password change not monitored
└─ Result: Attacker maintained access even if initial C2 blocked

DETECTION GAP #3: Pre-encryption activity (Days 13-14)
├─ Backup system access not monitored
├─ Shadow copy deletion not alerted
├─ Security tool disablement not detected
├─ Ransomware binary staging not inspected
└─ Result: No prevention of encryption or recovery option

DETECTION GAP #4: Encryption phase (Day 15)
├─ PsExec activity across multiple systems not correlated
├─ High file access rate not detected
├─ Bulk file encryption not triggered IDS alert
├─ Ransom note creation not inspected
└─ Result: 87% encryption before manual detection
```

**Detection Methods - What SHOULD Have Worked:**

```
ALERT 1: Golden Ticket Detection (Day 8)
Query: Search for Kerberos TGT with unusual attributes
└─ Event 4769 (Kerberos service ticket requested)
   └─ Ticket options = 0x40810000 (unusual flags)
   └─ Encryption type = 23 (RC4-HMAC, not default AES)
   └─ Client logon user = MACHINE$ (computer account - suspicious)

ALERT 2: Service Account Privilege Escalation (Day 10)
Query: Service account with domain admin group membership
└─ Event 4732 (Member added to global group)
   └─ New member: svc_system
   └─ Group: Domain Admins
   └─ Unexpected member addition by domain admin

ALERT 3: Shadow Copy Deletion (Day 14, 23:15)
Query: Command-line execution attempting to delete shadow copies
└─ Event 4688 (Process creation)
   └─ Command: vssadmin.exe delete shadows /all /quiet
   └─ Command: wmic shadowcopy delete
   └─ Command: powershell Remove-Item -Path "\\?\GlobalRoot\Device\..."

ALERT 4: Ransomware Detonation (Day 15, 23:47)
Query: Bulk file encryption / rapid file modification
└─ Endpoint alert: High rate of file writes (1000+ files/min)
└─ File types: .doc, .ppt, .xls, .pdf → .CONTI (all file types)
└─ Extensions added: .CONTI (ransomware signature)
└─ Parent process: services.exe or PsExec injection

Action: IMMEDIATE
├─ Isolate all affected systems from network (disconnect power to be safe)
├─ Restore from clean backups (if available)
├─ Notify law enforcement (FBI, CISA)
├─ Preserve evidence for forensics
└─ Activate incident response plan
```

**Hunting Queries for Post-Compromise Investigation:**

```
# PowerShell - Find suspicious processes running as service accounts
Get-Process | Where-Object {
  $_.UserName -like "*svc_*" -and 
  @("cmd.exe", "powershell.exe", "psexec.exe") -contains $_.Name
}

# WMI - Find shadow copy deletion attempts
Get-WmiObject Win32_ShadowCopy | Select Count
# Expected: 10-100 per system
# Ransomware result: 0 (all deleted)

# Event Log - Find golden ticket indicators
Get-WinEvent -FilterHashtable @{
  LogName = "Security"
  ID = 4769
  StartTime = (Get-Date).AddDays(-7)
} | Where {
  $_.Message -like "*Ticket Options*0x40810000*"
}

# Registry - Find DSRM password changes
Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DsrmAdminLogonBehavior"
# Normal: Not present
# Suspicious: Value = 0 (password-based logon allowed)

# File System - Find ransomware samples
Get-ChildItem -Path "C:\Windows\Temp" -Filter "*.exe" -File -Recurse |
  Where {$_.LastWriteTime -gt (Get-Date).AddDays(-7)}
```

**Kill Chain Breaker Checklist:**
```
☐ User behavior analytics (detecting abnormal data access)
☐ Backup immutability (cannot be deleted by standard accounts)
☐ Offline backup copies (not accessible from network)
☐ EDR configured for file encryption detection
☐ Event log monitoring for security tool disablement
☐ PsExec usage alerts (admin tool abuse)
☐ Golden Ticket detection (unusual Kerberos activity)
☐ Domain admin account monitoring
☐ Command auditing for dangerous commands (net, wmic, vssadmin)
☐ Ransomware signature detection (file extension changes)
☐ Network segmentation (backups isolated from production)
☐ Incident response runbook for ransomware (pre-written, tested)
```

---

## Breaking the Kill Chain - Defense in Depth Framework

### Summary Table

| Stage | Attacker Goal | Defense Layer 1 | Defense Layer 2 | Defense Layer 3 | KPI |
|---|---|---|---|---|---|
| 1. Reconnaissance | Gather intel | OSINT minimization | External monitoring | Threat intel feeds | 0 successful scans |
| 2. Weaponization | Create payload | Attack surface reduction | Patch management | Exploit monitoring | 0 usable exploits |
| 3. Delivery | Get payload in | Email filtering | User training | Sandbox analysis | <5% open rate |
| 4. Exploitation | Execute on target | System hardening | EDR detection | Exploit protection | <1% execution rate |
| 5. Installation | Establish persistence | AppWhitelist + Sysmon | File Integrity Monitor | EDR response | 0 persistence |
| 6. Command & Control | Remote access | Network egress filtering | Threat intel DNS block | EDR C2 detection | 0 C2 connections |
| 7. Actions on Objective | Achieve goal | Privilege separation | Behavioral analytics | Backup immutability | 0 data loss |

### Critical Control Priorities

**IMMEDIATE (Week 1):**
1. Enable Event Log forwarding (4624, 4625, 4720, 4732)
2. Configure SIEM alert for Event 4625 spike
3. Enable Sysmon on critical servers
4. Implement MFA for admin accounts

**SHORT-TERM (Month 1-2):**
1. Deploy EDR to all endpoints
2. Implement egress filtering
3. Configure network segmentation
4. Enable PowerShell logging

**LONG-TERM (Month 3-6):**
1. Full network segmentation implementation
2. Backup immutability implementation
3. Threat intelligence integration
4. Security awareness training rollout

---

## References

- Lockheed Martin: Cyber Kill Chain
- MITRE ATT&CK Framework
- NIST Cybersecurity Framework
- CIS Controls
- SANS Incident Handler Handbook

---

*Version History:*
- v2.1 (2026-02-19): Added real-world examples and detection procedures
- v2.0 (2026-01-15): Restructured with detection focus
- v1.0 (2025-11-20): Initial framework documentation