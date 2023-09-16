<p align="center">
<img src="assets/logo.png">
</p>
<h2 align="center">
Forensic Artifact Retrieval
</h2>


### What is it?

PowerHaul is a script to help Incident Responders gather forensically-useful artifacts from both local and remote hosts.  

The tool is designed to gather as many 'raw' artifacts as possible for easier use in downstream data analysis pipelines.

The tool is also designed to allow for flexible evidence specification via the input configuration file - collection directives can be one of three forms:
* Files - Specify file paths with filters and whether to check recursively or not.
* Commands - Specify commands to run - commands should output to some type of file and are executed via the PowerShell interpreter.
* Registry - Specify paths with relevant keys to filter on (if any) along with recursiveness.

### Usage

Commandline parameters are documented below.

```
.\PowerHaul.ps1 : Default Usage - collects all artifacts specified in config.json from the localhost into the current directory.
.\PowerHaul.ps1 -targets HOSTNAME1,HOSTNAME2 : Run PowerHaul against the provided hostnames.
.\PowerHaul.ps1 -target_file C:\targets.txt : Run PowerHaul against the line-delimited targets present in the specified text file.
.\PowerHaul.ps1 -creds : Tell PowerHaul to prompt the user for credentials to use.
.\PowerHaul.ps1 -evidence_dir C:\evidence : Tell PowerHaul where to store collected evidence.
.\PowerHaul.ps1 -config C:\config.json : Specify the path to a custom configuration file to use - by default, PowerHaul will look for 'config.json' in the current script directory.
```

### What is collected by default?
* Jumplists
* Prefetch Files
* Amcache HVE and LOGs
* Scheduled Tasks (Raw XML and formatted CSV)
* PowerShell Console History
* NTUSER.DAT Hives
* AppX Data
  * SYSTEM-installed apps
  * User-installed apps
  * Deleted Apps
  * State Repository
  * Program Data
* Asset Advisor Log
* Windows Drivers
* ShimSDB Files
* SRUDB
* User Access Logging (UAL)
* LNK Files
* Recent File Cache
* NET CLR Usage Logs
* Mini Dump Files
* System Log Files
* MOF Files
* Linux Profile Data
* WDI/WMI Logs
* Office Data
  * Backstage Cache
  * Document Cache
  * Diagnostic Files
  * Autosave Files
* Windows Push Notification DB
* Windows Event Logs
  * Security
  * Application
  * System
  * Task Scheduler Operational
  * PowerShell Operational
  * Shell Core Operational
  * TerminalServices-*
  * RemoteDesktopServices-*
* ProgramCompatAssistant
* BitmapCache
* Windows Timeline (Activites Cache)
* Windows Search Index
* ThumbCache
* USB Setup API Log
* Signature Catalog
* Startup Folders/XML
* Snippet Cache
* IIS Configuration Data
* Group Policy Files
* BITS DB
* Cortana DB
* WBEM Repository
* etc Directory
* Windows 10 Notification DB
* WER Files
* BITS DB/Related Files
* Cortana DB/Related Files
* Antivirus Logs
  * Avast
  * BitDefender
  * McAfee
  * Sophos
  * AVG
  * ESET
  * TrendMicro
  * Defender
* RAT Logs/Artifacts
  * AnyDesk
  * RealVNC
  * UltraVNC
  * TeamViewer
* DNS Cache
* Windows Services
* TCP Connections
* SMB Shares
* Defender Detections
* Startup Items (Win32_StartupCommand)
* Firewall Rules
* ARP Cache
* "Suspicious" Files
  * Specific extensions in specific paths
* Installed Software
* ActiveScript/CommandLine WMI Consumers
* Running Processes

### TODO

### Requirements

* WMI - Used for launching processes / retrieving data from remote hosts.
* Local Admin Privileges - Required for using WMI remotely, mapping drives, etc.
* SMB - Used for transferring data from remote hosts (Access via Drive Mapping such as \\TARGET\\C$\).
* VSS/ShadowCopies for targeting locked system files - otherwise these will be inaccessible.

### References
* https://github.com/EricZimmerman/KapeFiles/tree/master/Targets
* https://www.sans.org/
* https://github.com/ForensicArtifacts/artifacts
