## MITRE ATT&CK® Mapping for Lazarus Group

### DreamJob

| Reconnaissance | Resource Development | Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command & Control | Exfiltration |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ----| ---- | ---- | ---- | ---- |
| Search Open Websites/Domains (T1593) | Compromise Infrastructure (T1584) | Phishing (T1566) | Command and Scripting Interpreter (T1059) | Create or Modify System Process (T1543) |   | Obfuscated Files or Information (T1027) | OS Credential Dumping (T1003) | System Network Configuration Discovery (T1016) | Remote Services (T1021) | Archive Collected Data (T1560) | Application Layer Protocol (T1071) | Exfiltration Over C2 Channel (T1041) |
|   | Compromise Accounts (T1586) |   | User Execution (T1204) | Boot or Logon Autostart Execution (T1547) |   | Masquerading (T1036) | Network Sniffing (T1040) | Remote System Discovery (T1018) | Lateral Tool Transfer (T1570) |   | Proxy (T1090) |   |
|   | Develop Capabilities (T1587) |   | System Services (T1569) |   |   | Template Injection (T1221) | Unsecured Credentials (T1552) | Network Sniffing (T1040) |   |   | Data Encoding (T1132) |   |
|   |   |   |   |   |   |   | Credentials from Password Stores (T1555) | Account Discovery (T1087) |   |   | Remote Access Software (T1219) |   |
|   |   |   |   |   |   |   |   | Network Share Discovery (T1135) |   |   | Encrypted Channel (T1573) |   |

### JTrack

| Reconnaissance | Resource Development | Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Command & Control | Exfiltration |
| ---- | ---- | ---- | ---- | ---- | ---- | ---- | ---- | ----| ---- | ---- | ---- | ---- |
|   | Compromise Infrastructure (T1584) | Trusted Relationship (T1199) |   |   | Exploitation for Privilege Escalation (T1068) | Obfuscated Files or Information (T1027) | OS Credential Dumping (T1003) | Network Share Discovery (T1135) | Remote Services (T1021) | Archive Collected Data (T1560) | Application Layer Protocol (T1071) | Exfiltration Over C2 Channel (T1041) |
|   | Develop Capabilities (T1587) |   |   |   |   | Masquerading (T1036) |   |   | Lateral Tool Transfer (T1570) |   | Proxy (T1090) |   |
|   |   |   |   |   |   | Indicator Removal on Host (T1070) |   |   |   |   | Ingress Tool Transfer (T1105)  |   |
|   |   |   |   |   |   | Network Boundary Bridging (T1599) |   |   |   |   | Data Encoding (T1132) |   |
|   |   |   |   |   |   |   |   |   |   |   | Protocol Tunneling (T1572) |   |

## Commonly used TTP

|  Tactic  |  ID  |  Technique  |  Procedure  |  Detect and Mitigation</br>(From ATT&CK)  |  Defensive Tactics and Techniques</br>(From D3FEND) |
| -------- | ---- | ----------- |  ---------- | ----------------------- | --------------------------------- |
| Resource Development | [T1584.004](https://attack.mitre.org/techniques/T1584/004/) | Compromise Infrastructure: Server | Lazarus use the compromised server as a C2 server. | Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on related stages of the adversary lifecycle, such as during Command and Control. | -  |
| Resource Development | [T1587.001](https://attack.mitre.org/techniques/T1587/001/) | Develop Capabilities: Malware | Lazarus uses its own malware. | Much of this activity will take place outside the visibility of the target organization, making detection of this behavior difficult. Detection efforts may be focused on post-compromise phases of the adversary lifecycle. | - |
| Defense Evasion | [T1027](https://attack.mitre.org/techniques/T1027/) | Obfuscated Files or Information | Lazarus uses binary padding to add junk data([T1027.001](https://attack.mitre.org/techniques/T1027/001/)). </br> In addition, Lazarus uses packer such as VMProtect and Themida([T1027.002](https://attack.mitre.org/techniques/T1027/002/)). | [Mitigations] </br> M1049: Antivirus/Antimalware </br> Employ heuristic-based malware detection. Ensure updated virus definitions and create custom signatures for observed malware. </br></br> M1040: Behavior Prevention on Endpoint </br></br>[Detection] </br> - Depending on the method used to pad files, a file-based signature may be capable of detecting padding using a scanning or on-access based tool. When executed, the resulting process from padded files may also exhibit other behavior characteristics of being used to conduct an intrusion such as system and network information Discovery or Lateral Movement, which could be used as event indicators that point to the source file. </br> - Use file scanning to look for known software packers or artifacts of packing techniques. Packing is not a definitive indicator of malicious activity, because legitimate software may use packing techniques to reduce binary size or to protect proprietary code. | - [File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis)</br> 　- [File Content Rules](https://d3fend.mitre.org/technique/d3f:FileContentRules)</br> 　- [Dynamic Analysis](https://d3fend.mitre.org/technique/d3f:DynamicAnalysis) |
| Defense Evasion | [T1070](https://attack.mitre.org/techniques/T1070/) | Indicator Removal on Host | Lazarus deletes traces using timestomp, sdelete, del command, etc. | [Mitigations]</br> M1041: Encrypt Sensitive Information</br> Obfuscate/encrypt event files locally and in transit to avoid giving feedback to an adversary. </br></br>  M1029: Remote Data Storage</br> Automatically forward events to a log server or data repository to prevent conditions in which the adversary can locate and manipulate data on the local system. When possible, minimize time delay on event reporting to avoid prolonged storage on the local system.</br></br>  M1022: Restrict File and Directory Permissions</br> Protect generated event files that are stored locally with proper permissions and authentication and limit opportunities for adversaries to increase privileges by preventing Privilege Escalation opportunities. </br></br> [Detection]</br> File system monitoring may be used to detect improper deletion or modification of indicator files. Events not stored on the file system may require different detection mechanisms. | - [Process Analysis](https://d3fend.mitre.org/technique/d3f:ProcessAnalysis)</br> 　- [File Access Pattern Analysis](https://d3fend.mitre.org/technique/d3f:FileAccessPatternAnalysis)</br> - [User Behavior Analysis](https://d3fend.mitre.org/technique/d3f:UserBehaviorAnalysis)</br> 　- [Resource Access Pattern Analysis](https://d3fend.mitre.org/technique/d3f:ResourceAccessPatternAnalysis) |
| Credential Access | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | OS Credential Dumping: LSASS Memory | Lazarus dumps credential from LSASS using Mimikatz, procdump, etc. | [Mitigations]</br> M1043: Credential Access Protection </br> With Windows 10, Microsoft implemented new protections called Credential Guard to protect the LSA secrets that can be used to obtain credentials through forms of credential dumping. It is not configured by default and has hardware and firmware system requirements. It also does not protect against all forms of credential dumping. </br></br> M1028: Operating System Configuration </br> Consider disabling or restricting NTLM. Consider disabling WDigest authentication. </br></br> M1027: Password Policies </br> Ensure that local administrator accounts have complex, unique passwords across all systems on the network. </br></br> M1026: Privileged Account Management </br> Do not put user or admin domain accounts in the local administrator groups across systems unless they are tightly controlled, as this is often equivalent to having a local administrator account with the same password on all systems. Follow best practices for design and administration of an enterprise network to limit privileged account use across administrative tiers. </br></br> M1025: Privileged Process Integrity </br> On Windows 8.1 and Windows Server 2012 R2, enable Protected Process Light for LSA. </br></br> M1017: User Training </br> Limit credential overlap across accounts and systems by training users and administrators not to use the same password for multiple accounts. </br></br> [Detection]</br> Monitor for unexpected processes interacting with LSASS.exe. Common credential dumpers such as Mimikatz access LSASS.exe by opening the process, locating the LSA secrets key, and decrypting the sections in memory where credential details are stored. Credential dumpers may also use methods for reflective Process Injection to reduce potential indicators of malicious activity. </br> On Windows 8.1 and Windows Server 2012 R2, monitor Windows Logs for LSASS.exe creation to verify that LSASS started as a protected process. Monitor processes and command-line arguments for program execution that may be indicative of credential dumping. Remote access tools may contain built-in features or incorporate existing tools like Mimikatz. PowerShell scripts also exist that contain credential dumping functionality, such as PowerSploit's Invoke-Mimikatz module, which may require additional logging features to be configured in the operating system to collect necessary information for analysis. | - [CredentialHardening](https://d3fend.mitre.org/technique/d3f:CredentialHardening)</br> 　- [Multi-factor Authentication](https://d3fend.mitre.org/technique/d3f:Multi-factorAuthentication) |
| Lateral Movement | [T1021.002](https://attack.mitre.org/techniques/T1021/002/) | Remote Services: SMB/Windows Admin Shares | Lazarus uses the stolen credentials to copy and execute files to other devices using wmic commands and SMB tools. | [Mitigations] </br> M1037: Filter Network Traffic </br> Consider using the host firewall to restrict file sharing communications such as SMB. </br></br> M1035: Limit Access to Resource Over Network </br> Consider disabling Windows administrative shares. </br></br> M1027: Password Policies </br> Do not reuse local administrator account passwords across systems. Ensure password complexity and uniqueness such that the passwords cannot be cracked or guessed. </br></br> M1026: Privileged Account Management </br> Deny remote use of local admin credentials to log into systems. Do not allow domain user accounts to be in the local Administrators group multiple systems. </br></br> [Detection] </br> Ensure that proper logging of accounts used to log into systems is turned on and centrally collected. Windows logging is able to collect success/failure for accounts that may be used to move laterally and can be collected using tools such as Windows Event Forwarding. Monitor remote login events and associated SMB activity for file transfers and remote process execution. Monitor the actions of remote users who connect to administrative shares. Monitor for use of tools and commands to connect to remote shares, such as Net, on the command-line interface and Discovery techniques that could be used to find remotely accessible systems. | - [Network Traffic Analysis](https://d3fend.mitre.org/technique/d3f:NetworkTrafficAnalysis)</br> - [Network Isolation](https://d3fend.mitre.org/technique/d3f:NetworkIsolation) |
| Collection | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) | Archive Collected Data: Archive via Utility | Lazarus compress collected data prior to exfiltration using WinRAR. | [Mitigations] </br> M1047: Audit </br> System scans can be performed to identify unauthorized archival utilities. </br></br> [Detect] </br> Common utilities that may be present on the system or brought in by an adversary may be detectable through process monitoring and monitoring for command-line arguments for known archival utilities. This may yield a significant number of benign events, depending on how systems in the environment are typically used. </br> Consider detecting writing of files with extensions and/or headers associated with compressed or encrypted file types. Detection efforts may focus on follow-on exfiltration activity, where compressed or encrypted files can be detected in transit with a network intrusion detection or data loss prevention system analyzing file headers. | - [File Analysis](https://d3fend.mitre.org/technique/d3f:FileAnalysis) </br> 　- [File Content Rules](https://d3fend.mitre.org/technique/d3f:FileContentRules) </br> 　- [Process Spawn Analysis](https://d3fend.mitre.org/technique/d3f:ProcessSpawnAnalysis) |