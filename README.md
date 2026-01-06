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
| order by Timestamp asc
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

---

##  🚩 Flag 4: Directory Enumeration

**Objective**: Determine how attackers identified backup locations.

---
