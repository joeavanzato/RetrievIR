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
### What is collected in the default config.json?
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

### Building Custom Configurations

Configuration files describe forensic evidence to capture from a target endpoint - these files have 3 primary directives that can be used to describe the target data:
1. files
2. commands
3. registry

#### Files

File Collection Directives are described by 4 primary key attributes in addition to the name of the directive (which is used as the last folder name for evidence storage)
* category [string] - The category of the evidence - file and command based evidence will be grouped by this category.
* filter [array of strings] - Comma-separated filters to use for finding relevantly-named files/extensions - these are each individually run against each path in the specified directive.
* recursive [boolean] - Whether the file search should be recursive in nature.
* paths [array of strings] - The paths to hunt for relevant evidence.

There are a few optional parameters designed to help augment the parsing of evidence as well as collecting 'locked' evidence such as NTUSER.DAT hives, AmCache, etc.
* shadow [boolean] - Specifies whether the evidence must be collected from a newly-created Shadow Copy
* dir_removals [int] - Specifies how many path segments to remove from the front of the path
  * Example: Specifying dir_removal = 5 for a target evidence path such as C:\Users\*\AppData\Local\Apps\* will remove C:, Users, the username, AppData and Local, copying the remaining directory structure of Apps\* into the directive evidence location.

Any evidence path containing the pattern '\Users\*\' will be automatically added into a per-user folder undernear the primary evidence path. 

For example - evidence collected from C:\Users\Joe\Test\Test2\* will be stored at $EVIDENCE_DIRECTORY$\$CATEGORY\$DIRECTIVE_NAME\Joe\$EVIDENCE.

An example complete configuration file containing a single file-based directive is shown below:

```
{
	"files": {
        "WinSearchIndex": {
            "category": "Windows"
			"filter": ["*"],
			"recursive": false,
			"paths": [
				"%HOMEDRIVE%\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\GatherLogs\\SystemIndex\\*"
			]
		}
	}
}
```
This directive will check the specified path for any file with any extension, non-recursively and store all identified files at $EVIDENCE_DIRECTORY\Windows\WinSearchIndex.

```
{
	"files": {
        "Example": [
        {
            "category": "Windows"
			"filter": ["*.log"],
			"recursive": false,
			"paths": [
				"%HOMEDRIVE%\\ProgramData\\Microsoft\\Test\\*"
				
			],
			"dir_removals": 4
		},
        {
            "category": "Windows"
			"filter": ["*.txt", "*.db"],
			"recursive": true,
			"paths": [
				"%HOMEDRIVE%\\ProgramData\\Example\\*",
				"%HOMEDRIVE%\\ProgramData\\AnotherExample\\*"
			],
			"shadow": true
		}
		]
	}
}
```
The example above contains two distinct collection directives under the same module - all detected evidence will be stored in the same parent directory, 'Example', but each directive can have varying specifications.

Reviewing config.json will help users to understand the possibilities available in file-based directives.

#### Commands

Command directives are intended to specify commands which should run on the target host and output results to a file which will be transferred back to the machine running PowerHaul.  Command directives contain 3 primary components:

* category [string] - The category of the command, similar to files - this will group evidence at the parent-level directory.
* command [string] - The command to execute - each command must output to a file designated as '#FILEPATH#' - this is replaced dynamically in-line.
* output [string] - The final file name that the resulting evidence will be stored as.

An example directive is shown below:

```
{
  "commmands": {
        "DNSCache": {
                    "category": "Network",
                    "command": "Get-NetTcpConnection -ErrorAction SilentlyContinue | Select * | Export-Csv -NoTypeInformation -Path '#FILEPATH#'",
                    "output": "DNSCache.csv"
                },
        }
}
```

The directive above will launch the command on all targets and copy the resulting evidence into $EVIDENCE_DIR\Network\DNSCache\DNSCache.csv.

Commands are launched as Base64 PowerShell via WMI Process Creation - keep in mind there is a command-line character limit so launching very long scripts through this method is not supported - a 'file-based' command-launch will be implemented in the future to help enable the usage of very complex scripts to augment Incident Response efforts.

#### Registry

Registry directives collect key/value information from specified paths into a single JSON output file - each directive can contain 5 primary components, described below:

* category [string] - The category of the evidence - this will help group evidence by parent-directory.
* paths [array of strings] - The registry paths to check, in a format such as "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions"
* recursive [boolean] - Whether the registry search should be recursive.
* keys [array of strings] - Specifies specific key-names to store instead of storing all key/value pairs in identified registry paths.
* store_empty [boolean] - Specifies whether keys that do not have values should be stored.

An example registry directive is shown below:

```
{
	"registry": {
		"RDPCache": {
			"category": "RDP",
			"paths": ["HKEY_USERS\\*\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers"],
			"recursive": true,
			"keys": ["UsernameHint"],
			"store_empty": true
		}
	}
}
```

This will identify all paths recursively under the specified path (along with the current) and look for any key-pairs named 'UsernameHint' - any paths with empty values will not be recorded.

Registry directives are bundled into a single large script that is executed on the target host, with all results being stored in a JSON output file having the following example structure:

```
[
    {
        "name":  "RDPCache",
        "category":  "RDP",
        "items":  [
                      {
                          "path":  "HKEY_USERS\\S-1-5-21-63485881-451500365-4075260605-1001\\SOFTWARE\\Microsoft\\Terminal Server Client\\Servers\\34.227.81.6",
                          "values":  [
                                         {
                                             "type":  "SZ",
                                             "name":  "UsernameHint",
                                             "value":  "MicrosoftAccount\\Administrator"
                                         }
                                     ]
                      }
                  ]
    }
]
```

### Requirements

* WMI - Used for launching processes / retrieving data from remote hosts.
* Local Admin Privileges - Required for using WMI remotely, mapping drives, etc.
* SMB - Used for transferring data from remote hosts (Access via Drive Mapping such as \\TARGET\\C$\).
* VSS/ShadowCopies for targeting locked system files - otherwise these will be inaccessible.

### References
* https://github.com/EricZimmerman/KapeFiles/tree/master/Targets
* https://www.sans.org/
* https://github.com/ForensicArtifacts/artifacts
