# 🚩 Process Lineage Red Flags: Malicious Macros

## 📋 Concept Overview
During alert triage, analyzing **Process Lineage** (the parent-child relationship between executing processes) is one of the most reliable ways to identify malware execution and phishing attacks. 

## 🔍 The Scenario
An alert triggered for a suspicious PowerShell execution. Upon reviewing the process tree, I noticed the following:
* **Parent Process:** `winword.exe` (Microsoft Word)
* **Child Process:** `powershell.exe`
* **Command Line Argument:** `-ExecutionPolicy Bypass`

## 🧠 Analyst Assessment
Normal Microsoft Word operations do not require spawning command-line interfaces or scripting engines. When an application like Word, Excel, or PowerPoint acts as a parent process to `powershell.exe`, `cmd.exe`, or `msdt.exe`, it is a high-fidelity Indicator of Compromise (IoC) for a **Malicious Macro** embedded in a phishing document.

The `-ExecutionPolicy Bypass` flag further confirms malicious intent, as the attacker is attempting to circumvent native Windows security controls to execute a payload.

## 🛡️ Detection Strategy (Splunk/Sysmon)
To detect this in a SIEM, we monitor Sysmon **Event ID 1 (Process Creation)**. 

**Sample SPL Query:**
```spl
index=main sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 
| where match(ParentImage, "(?i)winword\.exe|excel\.exe|powerpnt\.exe") 
  AND match(Image, "(?i)powershell\.exe|cmd\.exe|wscript\.exe|cscript\.exe")
| table _time, ComputerName, User, ParentImage, Image, CommandLine
