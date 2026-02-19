# Incident Response Lifecycle & Procedures

**Version:** 2.0  
**Last Updated:** 2026-02-19  
**Classification:** Internal Use

---

## IR Framework: NIST Incident Response Lifecycle

The NIST framework defines four phases: **Preparation → Detection → Containment → Eradication → Recovery → Post-Incident**.

---

### Phase 1: PREPARATION

**Objective:** Establish capabilities before an incident occurs.

**Teams & Roles:**
```
Incident Response Team Structure:

IR Coordinator (1)
├─ Manages overall incident response
├─ Activates incident response team
└─ Reports to CISO

Technical Lead (1-2)
├─ Investigates technical aspects
├─ Preserves evidence
└─ Recommends containment actions

SOC Manager
├─ Monitors alerts
├─ Triages incidents
└─ Escalates when needed

SIEM Analyst (1+)
├─ Searches SIEM for related events
├─ Creates timeline
└─ Identifies scope of compromise

Network/Firewall Engineer
├─ Analyzes network traffic
├─ Implements firewall blocks
└─ Segments affected systems

Endpoint Engineer
├─ Collects forensic images
├─ Deploys patches
└─ Reimages compromised systems

System Administrator
├─ Manages backups
├─ Coordinates recovery
└─ Validates restoration

Legal/Compliance Officer
├─ Determines notification requirements
├─ Manages regulatory reporting
└─ Advises on evidence handling

Communications Manager
├─ Prepares customer notifications
├─ Handles media inquiries
└─ Updates stakeholders
```

**Tools & Resources:**

Required SOC tools:
- SIEM (Splunk, Sentinel, etc.) — logs from all sources
- EDR (CrowdStrike, Falcon, etc.) — endpoint visibility
- Forensic toolkit (Volatility, EnCase) — evidence collection
- IDS/IPS (Suricata, Zeek) — network analysis
- Threat intelligence platform (Shodan, VirusTotal) — enrichment

On-call schedule:
- 24/7 coverage for critical incidents
- Escalation procedures documented
- Call-out procedures (SMS, phone, email)
- Response time SLA: <15 minutes for critical

**Preparation Checklist:**
```
☐ IR plan documented and published
☐ IR team identified and trained
☐ Contact list current (phone, email, on-call)
☐ Communication templates prepared
☐ Forensic tools procured and tested
☐ SIEM configured with critical alert rules
☐ EDR agent deployed to all endpoints
☐ Backup procedures tested
☐ Recovery procedures documented
☐ Incident severity definitions documented
☐ Escalation procedures documented
☐ Annual IR training conducted
```

---

### Phase 2: DETECTION & ANALYSIS

**Objective:** Detect and confirm an incident has occurred.

**Detection Sources:**
```
1. Automated Alerts (SIEM)
   ├─ Malware detected (antivirus alert)
   ├─ Brute force attack (failed login spike)
   ├─ Unusual data access (DLP alert)
   └─ Network anomaly (IDS/IPS alert)

2. Manual Investigation
   ├─ System administrator notices performance issues
   ├─ User reports suspicious activity
   ├─ Routine log review identifies pattern
   └─ Anomaly detected during threat hunt

3. External Notification
   ├─ FBI/Law enforcement tip
   ├─ Third-party breach notification
   ├─ Customer reports suspicious activity
   └─ Breach notification service alert

4. EDR Alerts
   ├─ Suspicious process execution
   ├─ Process injection detected
   ├─ Unauthorized privilege escalation
   └─ C2 communication blocked
```

**Initial Assessment (First 15 minutes):**

```
CRITICAL QUESTIONS TO ANSWER:

1. What is the source of the alert?
   ├─ Is it a legitimate security tool?
   ├─ Is the source trusted?
   └─ Can we corroborate with another source?

2. What system is affected?
   ├─ Hostname or IP address?
   ├─ User account involved?
   └─ Criticality of the system (critical/important/low)?

3. When did it occur?
   ├─ Time alert was generated
   ├─ Time of actual incident (if different)
   └─ How long has it been undetected?

4. What is the severity?
   ├─ CRITICAL: Business-critical system compromised
   ├─ HIGH: Multiple systems affected or data theft
   ├─ MEDIUM: Single non-critical system, potential malware
   └─ LOW: False alarm or minor suspicious activity

5. What action is needed immediately?
   ├─ Isolate from network? (disconnect now, ask questions later)
   ├─ Preserve evidence? (memory dump, disk image)
   ├─ Block attacker access? (firewall rule, credential revoke)
   └─ Notify leadership? (CISO, CIO, CEO if critical)
```

**Incident Classification:**

```
Incident Types:

MALWARE INFECTION
├─ Signature: Trojan, ransomware, botnet
├─ Typical MTTD: 30 minutes - 7 days
├─ Response: Isolate, scan, clean/rebuild
└─ Data risk: High (data theft, encryption)

UNAUTHORIZED ACCESS
├─ Signature: Unknown user, privilege escalation
├─ Typical MTTD: Hours - weeks
├─ Response: Revoke credentials, change passwords
└─ Data risk: High (data theft, configuration changes)

DENIAL OF SERVICE
├─ Signature: Traffic spike, application crash
├─ Typical MTTD: Minutes (detected immediately)
├─ Response: Activate DDoS mitigation
└─ Data risk: Low (availability impact only)

DATA BREACH
├─ Signature: Large data exfiltration
├─ Typical MTTD: Days - months (often detected externally)
├─ Response: Preserve evidence, notify regulators
└─ Data risk: Critical (customer data exposure)

INSIDER THREAT
├─ Signature: Bulk data copy, unusual access patterns
├─ Typical MTTD: Days - months (behavioral analysis)
├─ Response: Disable access, investigate motives
└─ Data risk: Critical
```

**Severity Matrix:**

| Severity | Impact | Systems | Timeline | Action |
|----------|--------|---------|----------|--------|
| CRITICAL | Business halted | 10+ systems | Activate IR team immediately | Isolate, contain, coordinate response |
| HIGH | Major data loss or service degradation | 5-9 systems | Activate IR team within 1 hour | Investigate, contain, mitigate |
| MEDIUM | Limited impact, one system | 1-4 systems | Activate incident response within 4 hours | Monitor, investigate, remediate |
| LOW | Suspicious activity, no confirmed breach | 1 system | Handle during business hours | Investigate, document |

**Initial Response Actions:**

```
TIER 1 - Immediate (0-5 minutes):
├─ Document time of discovery
├─ Take screenshot/snapshot of current state
├─ DO NOT touch system (preserve evidence)
├─ DO NOT reboot system
├─ Alert on-call IR coordinator
└─ Notify manager/director

TIER 2 - Containment (5-30 minutes):
├─ IF CRITICAL: Isolate system (network cable disconnect)
├─ Gather initial information (system name, user, process)
├─ Review SIEM for related alerts
├─ Check if credentials are compromised
├─ IF DATA THEFT: Notify DLP team to block external upload
└─ Document initial findings in IR tracking system

TIER 3 - Investigation (30 min - 2 hours):
├─ Activate full incident response team
├─ Assign IR roles (lead, SOC analyst, forensics, etc.)
├─ Initiate incident log (timeline, actions, findings)
├─ Escalate to management/CISO
├─ Begin evidence preservation
└─ Start threat intelligence enrichment
```

**Evidence Preservation:**

```
Priority Order of Evidence Collection:

1. VOLATILE (Lost on reboot):
   ├─ Memory (RAM) - 1-2 GB per system
   ├─ Network connections (netstat -ano)
   ├─ Running processes (tasklist /v)
   ├─ Scheduled tasks (tasklist /sched)
   ├─ Open files (Get-OpenFile or Process Explorer)
   └─ Logged-in users (query user)
   
   Collection method:
   └─ Network isolation FIRST, THEN collect via USB drive
      (prevents C2 communication, but preserves volatiles)

2. SEMI-VOLATILE (Changes on reboot):
   ├─ Event logs (Security, System, Application)
   ├─ Recycle bin contents
   ├─ Temporary files
   ├─ Swap file contents
   └─ Prefetch files
   
   Collection method:
   └─ After volatile collection, before reboot

3. NON-VOLATILE (Survives reboot):
   ├─ Full disk image (bit-perfect copy)
   ├─ Registry hives
   ├─ File system
   └─ Browser history/cache
   
   Collection method:
   └─ After system isolated and volatiles collected
      Use forensic write-blocker to prevent modification
```

**Detection Phase Checklist:**
```
☐ Alert source verified (legitimate tool)
☐ Incident severity assigned
☐ Initial scope determined (1-10+ systems)
☐ IR team activated
☐ Initial evidence collected (screenshot, process list)
☐ System isolated from network (if critical)
☐ Timeline started (alert time vs incident time)
☐ Related alerts searched in SIEM
☐ Threat intelligence enrichment started
☐ Incident logged in tracking system
```

---

### Phase 3: CONTAINMENT

**Objective:** Stop the attack and prevent further damage.

**Short-Term Containment (Immediate):**

```
ACTIONS IN FIRST HOUR:

1. Isolate Compromised Systems:
   ├─ Unplug network cable (physical isolation)
   ├─ Alternative: Disable network interface via BIOS
   ├─ Leave system powered on (preserve volatiles)
   ├─ Document all connectivity before disconnection
   └─ Status: Contained (attacker cannot communicate)

2. Revoke Compromised Credentials:
   ├─ IF user account compromised:
   │  ├─ Disable user account (Active Directory)
   │  ├─ Force password reset
   │  └─ Sign out all active sessions
   ├─ IF service account compromised:
   │  ├─ Stop services using account
   │  ├─ Reset service account password
   │  └─ Update configuration in all applications
   └─ Status: Attacker cannot use stolen credentials

3. Block Known C2 Addresses:
   ├─ Add to firewall blocklist
   ├─ Add to DNS sinkhole
   ├─ Block at email gateway
   └─ Status: Attacker cannot communicate with compromised systems

4. Isolate from Backups:
   ├─ Stop/disconnect backup software (prevent backup of malware)
   ├─ Verify backups taken BEFORE incident date
   ├─ Mark backups as potentially compromised
   └─ Status: Recovery will use clean backups only
```

**Long-Term Containment (2-24 hours):**

```
ACTIONS TO PREVENT RE-INFECTION:

1. Patch Vulnerability:
   ├─ IF exploitation vector identified:
   │  ├─ Emergency patch deployment
   │  ├─ High-risk systems first (within 4 hours)
   │  ├─ All systems within 24 hours
   │  └─ Change management bypass authorized
   ├─ IF no patch available:
   │  ├─ Implement workaround (firewall rule, disable feature)
   │  └─ Vendor contact for emergency patch
   └─ Status: Vulnerability no longer exploitable

2. Detect Related Activity:
   ├─ Search SIEM for:
   │  ├─ Same source IP (attacker)
   │  ├─ Same malware hash
   │  ├─ Similar process patterns
   │  ├─ Same C2 domain/IP
   │  └─ Same user accounts
   ├─ Result: Identify ALL affected systems (not just initial)
   └─ Status: Full scope of compromise known

3. Implement Detection Rules:
   ├─ Create SIEM alerts for:
   │  ├─ Specific malware hashes
   │  ├─ Specific process patterns
   │  ├─ Specific file paths
   │  ├─ Specific registry changes
   │  └─ Specific C2 infrastructure
   └─ Status: Future occurrences detected immediately

4. Contain in Production:
   ├─ For non-critical systems:
   │  ├─ Install/update antivirus
   │  ├─ Run full system scan
   │  ├─ Monitor for signs of re-infection
   │  └─ Escalate to eradication if malware found
   ├─ For critical systems:
   │  ├─ Keep isolated
   │  ├─ Do not restore to production until eradicated
   │  └─ Plan rebuild/recovery
   └─ Status: Damage limited to contained systems
```

**Containment Phase Checklist:**
```
☐ Compromised system isolated (network disconnected)
☐ Related systems identified via SIEM search
☐ All affected systems isolated
☐ Compromised credentials revoked
☐ C2 addresses blocked (firewall, DNS)
☐ Detection rules created for malware signatures
☐ Vulnerability patched (or workaround implemented)
☐ Backup integrity verified
☐ Recovery timeline established
☐ Management updated on containment status
```

---

### Phase 4: ERADICATION

**Objective:** Remove all attacker tools, malware, and persistence mechanisms.

**Eradication Steps:**

```
1. MALWARE REMOVAL:
   ├─ Full antivirus scan (offline preferred)
   ├─ Malware-specific removal tools (Emotet removal, etc.)
   ├─ Manual removal of known malware:
   │  ├─ Delete executable files
   │  ├─ Remove registry entries
   │  ├─ Delete scheduled tasks
   │  ├─ Remove services
   │  └─ Clean browser extensions
   ├─ Verification: Run secondary antivirus (different vendor)
   └─ Status: No malware remains

2. PERSISTENCE REMOVAL:
   ├─ Scheduled tasks:
   │  └─ tasklist /sched | find "suspicious"
   │  └─ schtasks /delete /tn "suspiciously_named_task"
   ├─ Services:
   │  └─ Get-Service | Where Status -eq Running
   │  └─ Stop-Service -Name suspicious_service
   ├─ Registry Run keys:
   │  └─ Check HKCU/HKLM ...\Run and RunOnce
   │  └─ Remove suspicious entries
   ├─ Startup folder:
   │  └─ Check C:\Users\*\AppData\Roaming\...\Startup
   │  └─ Delete suspicious executables
   ├─ WinLogon entries:
   │  └─ Check HKLM\Software\Microsoft\Windows NT\...\WinLogon
   │  └─ Remove unauthorized entries
   └─ Status: Malware won't restart on reboot

3. BACKDOOR REMOVAL:
   ├─ Domain Admin accounts:
   │  └─ Check for unauthorized domain admin accounts
   │  └─ Delete (e.g., svc_backup created by attacker)
   ├─ RDP/SSH backdoors:
   │  └─ Disable RDP if not needed
   │  └─ Require MFA for RDP access
   └─ OS-level backdoors (rootkits):
   │  └─ More difficult to remove
   │  └─ Recommend full OS rebuild
   └─ Status: Attacker cannot use backdoors

4. FULL OS REBUILD (Recommended for Critical Systems):
   ├─ Procedure:
   │  ├─ Boot from clean installation media
   │  ├─ Wipe disk completely
   │  ├─ Fresh OS installation
   │  ├─ Apply all security patches
   │  ├─ Install approved applications
   │  ├─ Restore data from clean backup (pre-incident)
   │  └─ Verify system function
   ├─ Timeline: 4-8 hours per system
   └─ Status: System completely clean

5. VERIFICATION:
   ├─ Secondary antivirus scan (different vendor)
   ├─ Rootkit scan (specialized tools)
   ├─ Memory analysis (if malware loaded in RAM)
   ├─ Network baseline (normal traffic flow)
   ├─ Process review (all running processes legitimate?)
   ├─ Registry review (no suspicious modifications?)
   └─ Status: System verified as clean
```

**Evidence Preservation During Eradication:**

```
Important: Do not destroy evidence!

Before Eradication:
├─ Create complete forensic image (bit-perfect copy)
├─ Store offline for investigation/law enforcement
├─ Maintain chain of custody documentation
└─ Preserve memory dump from compromise time

During Eradication:
├─ Document every action taken
├─ Take screenshots before/after
├─ Record file/registry changes
└─ Maintain audit trail

After Eradication:
├─ Conduct forensic analysis on preserved image
├─ Identify root cause
├─ Document attack timeline
├─ Prepare forensic report
└─ Provide to law enforcement if needed
```

**Eradication Phase Checklist:**
```
☐ Malware identified and removed
☐ Persistence mechanisms documented
☐ Registry entries cleaned
☐ Services/tasks removed
☐ Unauthorized accounts deleted
☐ Backdoors removed or disabled
☐ OS rebuilds completed (critical systems)
☐ Antivirus scans confirm clean
☐ Forensic image preserved
☐ Eradication verified
```

---

### Phase 5: RECOVERY

**Objective:** Restore systems to normal operations.

**Recovery Steps:**

```
1. SYSTEM RESTORATION:
   ├─ IF rebuild required:
   │  ├─ Deploy clean OS from backup (3-5 hours)
   │  ├─ Apply latest patches
   │  ├─ Restore applications (pre-tested)
   │  ├─ Restore user data (from clean backup pre-incident)
   │  ├─ Verify connectivity and functionality
   │  └─ Return to production
   ├─ IF malware cleaned:
   │  ├─ Verify antivirus clean scan
   │  ├─ Verify system functionality
   │  ├─ Test network connectivity
   │  ├─ Monitor closely for re-infection
   │  └─ Return to production
   └─ Status: Systems operational

2. DATA RESTORATION:
   ├─ IF data was encrypted (ransomware):
   │  ├─ Determine decryption key source
   │  ├─ IF available: Decrypt from backup
   │  ├─ Verify data integrity
   │  └─ Restore to users
   ├─ IF data was modified:
   │  ├─ Restore from last clean backup (pre-incident)
   │  ├─ Notify users of data loss (work redone?)
   │  └─ Document impact
   └─ Status: Data available

3. MONITORING PHASE (Days after recovery):
   ├─ Increased monitoring frequency:
   │  ├─ SIEM alerts checked every 1 hour
   │  ├─ System logs reviewed twice daily
   │  ├─ Antivirus scans scheduled daily
   │  └─ Network traffic reviewed for anomalies
   ├─ Watch for re-infection signs:
   │  ├─ Malware re-detection
   │  ├─ New unauthorized accounts
   │  ├─ Unusual network traffic
   │  ├─ Process execution anomalies
   │  └─ File system changes
   ├─ Duration: 2 weeks minimum for critical systems
   └─ Status: No signs of re-infection

4. VALIDATION:
   ├─ Functionality testing:
   │  ├─ All required services running
   │  ├─ User access working
   │  ├─ Data accessible
   │  └─ Performance acceptable
   ├─ Security testing:
   │  ├─ No malware detected
   │  ├─ Patches current
   │  ├─ Security controls functioning
   │  └─ Logs being collected
   └─ Status: System ready for normal operation
```

**Recovery Time Objectives (RTO):**

```
System Priority vs Recovery Time:

CRITICAL (RTO 1-4 hours):
├─ Domain Controllers
├─ Email servers
├─ File servers
├─ Backup servers
└─ Payment systems
   └─ Dedicated redundancy + instant failover

IMPORTANT (RTO 4-24 hours):
├─ Department servers
├─ Business application servers
├─ Database systems
└─ Development systems
   └─ Restore from recent backup + patches

STANDARD (RTO 1-3 days):
├─ Office workstations
├─ Print servers
├─ Non-critical applications
└─ Testing systems
   └─ Rebuild from image + configuration

LOW PRIORITY (RTO 1-2 weeks):
├─ Archived systems
├─ Backup systems
├─ Test/dev environments
└─ Rarely-used applications
   └─ Restore on demand
```

**Recovery Phase Checklist:**
```
☐ Patching plan executed
☐ System rebuilds completed
☐ Data restoration verified
☐ User access tested
☐ Application functionality verified
☐ Monitoring threshold reset
☐ Enhanced monitoring period activated (2 weeks)
☐ No re-infection detected
☐ Return to normal operations authorized
☐ Recovery completion documented
```

---

### Phase 6: POST-INCIDENT ACTIVITIES

**Objective:** Learn from incident and improve security.

**Root Cause Analysis (RCA):**

```
Five Whys Technique:

Incident: Ransomware infection of file server

Why 1: Why was file server infected?
└─ Because user opened malicious email attachment

Why 2: Why did user open attachment?
└─ Because email passed through spam filter

Why 3: Why did spam filter miss malicious email?
└─ Because malware was obfuscated/polymorphic, unknown signature

Why 4: Why wasn't malware detected after execution?
└─ Because EDR agent not installed on file server

Why 5: Why wasn't EDR agent deployed to file servers?
└─ Because file servers were excluded from deployment scope

ROOT CAUSE: Incomplete EDR deployment (policy gap)

Corrective Actions:
├─ Deploy EDR to ALL systems (including file servers)
├─ Implement email sandboxing
├─ Enable file server monitoring
├─ Update EDR alert rules
└─ Quarterly EDR agent compliance verification
```

**Lessons Learned Document:**

```
Template:

WHAT HAPPENED:
├─ Timeline of events
├─ Attack progression
├─ Detection timeline
├─ Response timeline
└─ Outcome

WHAT WORKED WELL:
├─ Detection was fast (MTTD <1 hour)
├─ IR team mobilized quickly
├─ Evidence preserved correctly
├─ Communication to stakeholders clear
└─ Recovery completed within RTO

WHAT DIDN'T WORK:
├─ EDR agent not on file servers (gap in visibility)
├─ Email sandboxing not deployed (allowed malware delivery)
├─ Backup process allowed backup of infected files (data restored infected)
├─ SOC didn't recognize attack pattern (training gap)
└─ User reported as low-priority alert (alert tuning issue)

WHAT WE'RE CHANGING:
1. EDR deployment to 100% of systems within 30 days
2. Email sandboxing implementation within 60 days
3. Backup isolation (immutable, offline copies) within 90 days
4. SOC training on ransomware patterns
5. Alert tuning to reduce false positives
6. Quarterly IR drills to test procedures
7. Update incident response playbook with ransomware procedures

RESPONSIBLE PARTIES & DEADLINES:
├─ EDR deployment: SecOps team, 30-day deadline
├─ Email sandboxing: Email team, 60-day deadline
├─ Backup isolation: Infrastructure team, 90-day deadline
├─ SOC training: CISO, quarterly
├─ Alert tuning: SOC manager, ongoing
└─ IR drills: IR coordinator, quarterly
```

**Metrics & KPIs Reviewed:**

```
What Happened During This Incident:

1. Detection Metrics:
   ├─ MTTD (Mean Time to Detect): 45 minutes
   ├─ Benchmark: <1 hour (PASSED)
   ├─ Improvement: Better than expected
   └─ Action: Maintain current detection tuning

2. Response Metrics:
   ├─ MTTR (Mean Time to Respond): 2 hours
   ├─ Benchmark: <4 hours (PASSED)
   ├─ Improvement: Team mobilization was swift
   └─ Action: Maintain on-call rotation

3. Recovery Metrics:
   ├─ MTRC (Mean Time to Recovery): 6 hours
   ├─ Benchmark: <24 hours (PASSED)
   ├─ Improvement: Backup restoration worked correctly
   └─ Action: Continue backup testing

4. Data Loss:
   ├─ Data compromised: 2.3 GB customer data
   ├─ Data lost: 0 (backup intact)
   ├─ Benchmark: 0 (PASSED)
   └─ Action: Notify affected customers (regulatory requirement)

5. System Availability:
   ├─ Systems down: 1 file server
   ├─ Duration: 6 hours
   ├─ Benchmark: <24 hours (PASSED)
   └─ Action: Implement redundancy (2 file servers) within 60 days
```

**Post-Incident Checklist:**
```
☐ Timeline documented (complete attack progression)
☐ Root cause analysis completed
☐ Lessons learned document written
☐ Corrective actions identified with owners/deadlines
☐ Legal/compliance notification completed
☐ Customer/stakeholder notification (if required)
☐ Law enforcement report filed (if applicable)
☐ Insurance claim filed (if applicable)
☐ Metrics reviewed vs benchmarks
☐ IR playbook updated
☐ Staff debriefing conducted
☐ Incident case closed (after 30-day monitoring)
```

---

## Incident Response Decision Tree

```
INCIDENT DETECTED
        │
        ▼
    Is this real?
    │
    ├─ NO → False alarm, document, close
    │
    └─ YES
        │
        ▼
    Severity level?
    │
    ├─ CRITICAL (business down, multiple systems)
    │  └─ Immediate IR team activation, executive notification
    │
    ├─ HIGH (1-2 critical systems or data theft)
    │  └─ IR team within 1 hour, director notification
    │
    ├─ MEDIUM (non-critical system, potential malware)
    │  └─ Response within 4 hours, manager notification
    │
    └─ LOW (suspicious activity, likely false positive)
       └─ Investigate during business hours
```

---

## References & Templates

- NIST Incident Response Handbook
- SANS Incident Handling Flowchart
- CIS Top 20 Controls
- Incident response playbooks (malware, ransomware, insider threat)

---

*Document Maintenance:*
- Review annually
- Update playbooks quarterly
- Conduct IR drills quarterly
- Update contact list monthly