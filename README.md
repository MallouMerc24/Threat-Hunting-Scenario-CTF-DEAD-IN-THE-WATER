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

- **SIEM Platform:**: Microsoft Log Analytics Workspace  
- **Query Language:**: Kusto Query Language (KQL)
- **Primary Focus**: Backup infrastructure compromise and ransomware deployment

  ---
  
##  🚩 Flag 1: Lateral Movement - Remote Access 

**Objective**: Identify the remote access command used to pivot into backup infrastructure.
