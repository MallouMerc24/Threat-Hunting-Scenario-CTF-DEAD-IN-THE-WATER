# 🕵️‍♂️ Threat Hunt Report: Dead In The Water

## 🎯 Scenario
One week after an initial compromise, the organization returns from the weekend to a worst case scenario: ransom notes across every system. This was not a smash and grab operation. The attackers spent days methodically dismantling recovery capabilities before deploying ransomware. 

  <ins>This threat hunt reconstructs how the attackers:<ins>
- Pivoted into backup infrastructure
- Destroyed recovery data
- Rapidly deployed ransomware across Windows systems
- Disabled every viable recovery mechanism

---

## 🛠️ Investigation Environment

- **SIEM Platform:** Microsoft Log Analytics Workspace  
- **Query Language:** Kusto Query Language (KQL)
- **Primary Focus:** Backup infrastructure compromise and ransomware deployment

  ---

## 🐧 PHASE 1: LINUX BACKUP SERVER COMPROMISE (FLAGS 1-12)

  ---
##  🚩 Flag 1: Lateral Movement - Remote Access 

**Objective**: Identify the remote access command used to pivot into backup infrastructure.

Under MITRE ATT&CK T1021.004 (Remote Services: SSH), the command ssh backup-admin@10.1.0.189 was executed, indicating remote access to the backup server using the backup-admin account. This activity occurred at 2025-11-20T14:19:46.1092202Z and reflects lateral movement via authenticated SSH access.

<img width="690" height="28" alt="image" src="https://github.com/user-attachments/assets/e2b51c76-7e7f-4129-ab53-1963c664e701" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName =~ "adminpc"
| where FileName == "ssh.exe"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| order by Timestamp dsc
```

**Notes:** This SSH connection represents the attacker’s pivot from a compromised workstation into critical backup infrastructure.

---

##  🚩 Flag 2: Attack Source Identification

**Objective**: Identify the IP address that initiated the SSH connection.

Under MITRE ATT&CK T1021.004 (Remote Services: SSH), investigation identified 10.1.0.108 as the source IP that initiated the SSH connection. This activity was recorded at 2025-11-25T05:39:22.191096Z, indicating authenticated remote access consistent with lateral movement behavior.

<img width="760" height="31" alt="image" src="https://github.com/user-attachments/assets/138e1def-c17c-4e20-8ed5-61446849318e" />

**KQL Query**:
```kql
DeviceProcessEvents
DeviceLogonEvents
| where DeviceName contains "BackupSrv"
| where LogonType == "Network"
| project Timestamp, DeviceName, RemoteIP, AccountName, ActionType
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| order by Timestamp dsc
```

**Notes:** Identifying the originating IP allows defenders to isolate the compromised host and understand lateral movement paths.

---

##  🚩 Flag 3: Compromised Account 

**Objective**: Identify the account used to access the backup server.

Under MITRE ATT&CK T1078.002 (Valid Accounts: Domain Accounts), analysis confirmed that the **backup-admin** account was used to access the backup server. The SSH syntax (username@host) directly reveals the compromised administrative account, indicating abuse of valid credentials with elevated backup privileges.

---

##  🚩 Flag 4: Directory Enumeration

**Objective**: Determine how attackers identified backup locations.

Under MITRE ATT&CK T1083 (File and Directory Discovery), the command **ls --color=auto -la /backups/** was executed, indicating that the attacker enumerated files and directories within the backup location. This activity occurred at 2025-11-25T05:47:51.749736Z and reflects reconnaissance efforts to identify accessible backup data and assess its contents.

<img width="783" height="180" alt="image" src="https://github.com/user-attachments/assets/43c4fea3-f68b-432a-a73e-110d1fd36fdb" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "Backupsrv"
| where ActionType == "ProcessCreated"
| where FileName == "ls"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| order by Timestamp desc
```

**Notes:** This command confirms attackers were mapping backup locations to identify targets for destruction.

---

##  🚩 Flag 5: Backup Archive Discovery

**Objective**: Identify how attackers searched for backup archives.

Under MITRE ATT&CK T1083 (File and Directory Discovery), the command *find /backups -name *.tar.gz** was executed, indicating that the attacker searched the backup directory for compressed archive files. This activity reflects reconnaissance behavior aimed at identifying valuable backup data for potential exfiltration or destruction.

<img width="806" height="165" alt="image" src="https://github.com/user-attachments/assets/49bbc710-8ecf-48c6-8b13-333912217b27" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName == "find"
| where ProcessCommandLine has_any ("tar", ".tar", ".tar.gz", ".tgz")
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| order by Timestamp dsc
```

**Notes:** Searching for compressed archives indicates intent to locate high-value backup data.

---

##  🚩 Flag 6 – Account Enumeration

**Objective**: Identify how local accounts were enumerated.

---

##  🚩 Flag 7: Scheduled Job Reconnaissance

**Objective**: Identify how backup schedules were discovered.

---

##  🚩 Flag 8: External Tool Download

**Objective**: Identify tools downloaded from external infrastructure.

---
