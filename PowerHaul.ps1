# Goals
# Collect specified forensic evidence from local and remote devices
# Collection of files based on JSON Configuration module
# Requirements
# WMI
# SMB or WinRM for accessing files on remote hosts
#

# General Thought Process
# Configuration file will specify files, registry keys or commands to execute on local or remote hosts
# Target List will be provided via command-line or file - no list means localhost only
# If targeting is specified, user should specify whether SMB or WinRM will be used for file-transfer capabilities to retrieve evidence from remote hosts
# If none is specified, SMB will be assumed.
# First - Power


[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false, HelpMessage = 'The fully-qualified file-path where evidence should be stored, defaults to $PSScriptRoot\evidence')]
	[string]$evidence_dir = "$PSScriptRoot\evidence",

	[Parameter(Mandatory = $false, HelpMessage = 'The fully-qualified file-path for the configuration file, defaults to $PSScriptRoot\config.json')]
	[string]$config = "$PSScriptRoot\config.json",

	[Parameter(Mandatory = $false, HelpMessage = 'Comma-delimited list of target computers - leaving blank will only target "127.0.0.1" (localhost).')]
	[array]$targets,

	[Parameter(Mandatory = $false, HelpMessage = 'Line-delimited list of target computers - if specified, -targets parameter will be ignored.')]
	[string]$target_file,

	[Parameter(Mandatory = $false, HelpMessage = 'If specified, will prompt for credentials to use for remote operations (if not using current user).')]
	[switch]$creds,

	[Parameter(Mandatory = $false, HelpMessage = 'If specified, will setup a Shadow Copy to access locked system files.')]
	[switch]$vss,

	[Parameter(Mandatory = $false, HelpMessage = 'Method to use for file-collection - either SMB or WinRM')]
    [ValidateSet(
		"SMB",
        "WinRM"
	)]
	[string]$method
)

$global_configuration = [hashtable]::Synchronized(@{})
$global_configuration.hostname = hostname
$log_path = $PSScriptRoot + "\PowerHaulAudit.log"

$shadow_stamp = (Get-Date).toString("HH:mm:ss") -replace (":","_")
$shadowcopy_name = "powerhaul_copy_$shadow_stamp"
$shadowcopy_output_status_file = "powerhaul_vss_status_$shadow_stamp"
if ($vss) {
    $root = $env:systemdrive+"\"+$shadowcopy_name
} else {
    $root = $env:systemdrive
}


# We will send the functions to a remote computer and output the result to a file at C:\Windows\temp\powerhaul_vss_check.txt
# If shadow creation is successful, file contents will contain below:
# SUCCESS:$SHADOWID
# If it is a failure, instead we will store only the below:
# FAILURE
# Below functions modified From JJ Fulmer awesome answer at https://stackoverflow.com/questions/14207788/accessing-volume-shadow-copy-vss-snapshots-from-powershell

$new_shadow_script = "
function New-ShadowLink {
    `$linkPath=`"`$(`$ENV:SystemDrive)\$shadowcopy_name`"

    try {
        `$class=[WMICLASS]`"root\cimv2:win32_shadowcopy`";
        `$result = `$class.create(`"`$ENV:SystemDrive\`", `"ClientAccessible`");
        `$shadow = Get-CimInstance -ClassName Win32_ShadowCopy | Where-Object ID -eq `$result.ShadowID
        `$target = `"`$(`$shadow.DeviceObject)\`";
        `$shadowid = `$shadow.ID
        Invoke-Expression -Command `"cmd /c mklink /j '`$linkPath' '`$target'`";
        Set-Content -Path C:\Windows\Temp\$shadowcopy_output_status_file.txt -Value SUCCESS:`$shadowid
    } catch {
        Set-Content -Path C:\Windows\Temp\$shadowcopy_output_status_file.txt -Value 'FAILURE:'
    }
}
New-ShadowLink
"
$new_shadow_bytes = [System.Text.Encoding]::Unicode.GetBytes($new_shadow_script)
$new_shadow_b64 = [Convert]::ToBase64String($new_shadow_bytes)
$new_shadow_command = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $new_shadow_b64

$remove_shadow_script = "
function Remove-ShadowLink {
    `$linkPath=`"`$(`$ENV:SystemDrive)\$shadowcopy_name`"
    `$data = Get-Content C:\Windows\Temp\$shadowcopy_output_status_file.txt
    `$split = `$data -split `":`"
    if (`$split[0] -eq `"SUCCESS`"){
        `$shadowid = `$split[1]
        vssadmin delete shadows /shadow=`$shadowid /quiet
        try {
            Remove-Item -Force -Recurse `$linkPath -ErrorAction Stop;
        }
        catch {
            Invoke-Expression -Command `"cmd /c rmdir /S /Q '`$linkPath'`";
        }
    } else {
    }
}
Remove-ShadowLink
"
$remove_shadow_bytes = [System.Text.Encoding]::Unicode.GetBytes($remove_shadow_script)
$remove_shadow_b64 = [Convert]::ToBase64String($remove_shadow_bytes)
$remove_shadow_command = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $remove_shadow_b64

function Create-Directory ($dir) {
    Log-Message "[+] Creating Evidence Directory: $dir" -quiet $true
    if (Test-Path $dir){
        Log-Message "[!] Directory already exists: $dir" -quiet $true
        return
    }
    try
    {
        New-Item -Path $dir -ItemType Directory | Out-Null
        Log-Message "[!] Evidence Directory Created!" -quiet $true
    }catch{
        Log-Message "[!] Could not create directory: $dir" $true
    }
}

function Log-Message ($msg, $error, $color, $quiet){
    $timestamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    if (-not $color){
        $color = "White"
    }
    if (-not $quiet){
        $quiet = $false
    }
    if ($error){
        Write-Warning $msg
    } elseif ($quiet){

    } else{
        Write-Host $msg -ForegroundColor $color
    }
    Add-Content -Path $log_path -Value "$timestamp - $msg"
}

function Get-Configuration {
    if (-not (Test-Path $config)){
        Log-Message "Could not find specified configuration file: $config" $true
        Log-Message "[*] Please double check the specified file exists!"
        Log-Message "[!] Exiting..."
        exit
    }
    try {
        $data = Get-Content $config -Raw | ConvertFrom-Json
    } catch {
        Log-Message "[!] Error reading/parsing specified configuration file!" $true
        Log-Message "[!] Exiting..."
        exit
    }

    Log-Message "[!] Configuration Summary:"
    if ($data.files){
        ForEach ($i in $data.files){
            $name = $i.psobject.Properties.Name
            $file_dir_count = $name | Measure-Object
        }
        Log-Message "[+] File Collection Directives: $($file_dir_count.Count)"
    } else {
        Log-Message "[+] File Collection Directives: 0"
    }
    if ($data.registry){
        ForEach ($i in $data.registry){
            $name = $i.psobject.Properties.Name
            $reg_dir_count = $name | Measure-Object
        }
        Log-Message "[+] Registry Collection Directives: $($reg_dir_count.Count)"
    } else {
        Log-Message "[+] Registry Collection Directives: 0"
    }
    if ($data.commands){
        ForEach ($i in $data.commands){
            $name = $i.psobject.Properties.Name
            $command_count = $name | Measure-Object
        }
        Log-Message "[+] Command Collection Directives: $($command_count.Count)"
    } else {
        Log-Message "[+] Command Collection Directives: 0"
    }

    return $data
}

function Get-Targets {
    $target_list = New-Object -TypeName "System.Collections.ArrayList"
    if (-not $targets -and -not $target_file){
        $target_list.Add($global_configuration.hostname) | Out-Null
        return $target_list
    } elseif ($target_file){
        if (-not (Test-Path $target_file)){
            Log-Message "[!] Could not find specified target file: $target_file" $true
            Log-Message "[!] Exiting..."
            exit
        }
        $targets = Get-Content $target_file
        return $targets
    } elseif ($targets){
        if ($targets -match ","){
            $targets_new = $targets.Split(",")
            return $targets_new
        } else {
            $target_list.Add($targets) | Out-Null
            return $target_list
        }
    }
}


function Start-Jobs ($computer_targets){
    Log-Message "[+] Starting Collections..."

    $evidence_dir_replace = $evidence_dir -Replace (":", "$")
    $share_map_script = "
        New-PSDrive -Credential $($global_configuration.credential) -Name PowerHaulDrive -PSProvider FileSystem -Root '\\$($global_configuration.hostname)\$evidence_dir_replace';
    "
    $script_bytes = [System.Text.Encoding]::Unicode.GetBytes($share_map_script)
    $base64_script = [Convert]::ToBase64String($script_bytes)
    $full_command = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand "+$base64_script
    #Write-Host $full_command

    foreach ($target in $computer_targets){
        Log-Message "[+] Targeting: $target"
        $current_evidence_dir = $evidence_dir + "\" + $target
        Create-Directory $current_evidence_dir
        $status = Create-Shadow $target
        if ($status -eq 1){
            Log-Message "[!] [$target] Shadow Created Successfully!"
            Get-Files $target $current_evidence_dir $true
        } else {
            Log-Message "[!] [$target] Shadow Failure - System/Locked Files will be unavailable!"
            Get-Files $target $current_evidence_dir $false
        }
        #Run-Commands $target $current_evidence_dir
        #Get-Registry $target $current_evidence_dir
        Delete-Shadow $target
    }
}

function Remove-Front-Dirs ($path, $count, $tmp_dir, $shadow){
    # Receives a fully-qualified path to a file as well as a count of how many 'segments' should be removed from the front
    # Helps with 'relative' copy-paste operations where we want to maintain a certain structure beyond a point.
    # For example, passing "C:\Windows\App\Test\icon.png",3 will return "Test\icon.png"
    # Passing "C:\Windows\App\Test\icon.png",2 would return "App\Test\icon.png"
    #Write-Host $path
    $removes = 0
    $max_index = $count - 1 + 4
    if ($shadow){
        $max_index += 1
    }
    $split_path = $path.Split("\")
    For ($counter=0; $counter -lt $max_index; $counter++){
        $first, $split_path = $split_path
    }
    $new_path = ""
    $last_element = $split_path[-1]
    ForEach($path_element in $split_path){
        if ($path_element -eq $last_element){
            $new_path += $path_element
        } else {
            $new_path += $path_element + "\"
            $tmp_dir_evidence = $tmp_dir + "\" + $new_path.Trim("\")
            Create-Directory $tmp_dir_evidence
        }
    }
    #$new_path = $new_path.Trim("\")
    #Write-Host $new_path
    return $new_path

}

function Get-Files ($target, $current_evidence_dir, $root_replace) {
    # TODO - Make user dir for any path which falls under C:\users\ and use as appropriate as base evidence directory
    ForEach ($object in $global_configuration.config.files){
        $obj_names = $object.psobject.Properties.Name
        ForEach ($category in $obj_names){
            Log-Message "[+] [$target] Collecting: $category"
            ForEach ($item in $object.$category){
                ForEach ($directive in $item){
                    $file_evidence_dir = $current_evidence_dir + "\" + $directive.category + "\" + $category
                    if (-not ($root_replace) -and $directive.shadow){
                        Log-Message "[+] [$target] Skipping: $category - Requires Volume Shadow which was unsuccessful!"
                        continue
                    }
                    ForEach ($path in $directive.paths){
                        if ($root_replace -and $directive.shadow){
                            $shadow_ok = $true
                            $tmp_path = $path -replace ("%HOMEDRIVE%", "\\$target\C$\$shadowcopy_name")
                        }
                        else {
                            $shadow_ok = $false
                            $tmp_path = $path -replace ("%HOMEDRIVE%", "\\$target\C$")
                        }
                        $path_replace = $tmp_path -replace ("\*",".*")
                        if ($global_configuration.credential){
                            Write-Host "CREDS"
                            # TODO - possibly map drive but probably not required in most situations if access is already present.
                        }
                        try {
                            $file_list_map = @{}
                            $file_list = New-Object -TypeName "System.Collections.ArrayList"
                            ForEach ($filter in $directive.filter){
                                $files = $null
                                $FailedItems = $null
                                try {
                                    if ($directive.recursive){
                                        $files = Get-ChildItem -Path "$tmp_path" -Recurse -Filter $filter -Force -ErrorVariable FailedItems -ErrorAction SilentlyContinue #| Where {! $_.PSIsContainer }
                                    } else {
                                        $files = Get-ChildItem -Path "$tmp_path" -Filter $filter -Force -ErrorVariable FailedItems -ErrorAction SilentlyContinue #| Where {! $_.PSIsContainer }
                                    }
                                } catch {
                                    Log-Message $_.Exception.GetType().FullName $true
                                }
                                ForEach ($failure in $FailedItems){
                                    if ($failure.Exception -is [UnauthorizedAccessException]){
                                        Log-Message "[!] [$target] Unauthorized Access Exception (Reading): $($failure.TargetObject)" $false "red"
                                    } elseif ($failure.Exception -is [ArgumentException]){
                                        Log-Message "[!] [$target] Invalid Argument Specified (Reading): $($failure.TargetObject)" $false "red"
                                    }
                                }
                                foreach ($f in $files){
                                    $file_list.Add($f) | Out-Null
                                }
                            }
                        } catch {
                            Log-Message "Error Processing Path: $tmp_path" $true
                        }
                        if ($file_list.Count -ne 0){
                            Create-Directory $file_evidence_dir
                        }
                        #Write-Host "FILES TO COPY: $($file_list.Count)"
                        ForEach ($file in $file_list){
                            # If the file we are attempting to copy exists under a specific user directory (Jumplists, etc) then we will store it under the relevant users name - $evidence_dir\jumplists\$USERNAME\$file
                            try {
                                if ($($file.FullName) -match ".*\\users\\(?<user>[^\\]*)\\.*"){
                                    $tmp_user_evidence_dir = $file_evidence_dir + "\" + $Matches.user
                                    Create-Directory $tmp_user_evidence_dir
                                    if ($directive.dir_removals){
                                        $new_dest_path = Remove-Front-Dirs $file.FullName $directive.dir_removals $tmp_user_evidence_dir $shadow_ok
                                        $dest_path = $tmp_user_evidence_dir + "\" + $new_dest_path
                                    } else {
                                        $dest_path = $tmp_user_evidence_dir
                                    }
                                } else {
                                    if ($directive.dir_removals){
                                        $new_dest_path = Remove-Front-Dirs $file.FullName $directive.dir_removals $file_evidence_dir $shadow_ok
                                        $dest_path = $file_evidence_dir + "\" + $new_dest_path
                                    } else {
                                        $dest_path = $file_evidence_dir
                                    }
                                }

                            } catch{
                                Log-Message "[!] [$target] Error processing file: $($file.FullName)" $false "red"
                                continue
                            }
                            #Write-Host "SOURCE: $($file.FullName)"
                            #Write-Host "DEST: $dest_path"
                            $FailedCopies = $null
                            try {
                                Copy-Item "$($file.FullName)" "$dest_path" -Force -ErrorVariable FailedCopies -ErrorAction SilentlyContinue
                            } catch {}
                            ForEach ($failure in $FailedCopies){
                                if ($failure.Exception -is [UnauthorizedAccessException]){
                                    Log-Message "[!] [$target] Unauthorized Access Exception (Copying): $($failure.TargetObject)" $false "red"
                                } elseif ($failure.Exception -is [ArgumentException]){
                                        Log-Message "[!] [$target] Invalid Argument Specified (Copying): $($failure.TargetObject)" $false "red"
                                } elseif ($failure.Exception -is [System.IO.IOException]){
                                        Log-Message "[!] [$target] Unable to access in-use file (Copying): $($failure.TargetObject)" $false "red"
                                }
                            }
                            #try {
                            #    Copy-Item "$($file.FullName)" "$dest_path" -Force
                            #} catch {
                            #    Write-Host "SOURCE: $($file.FullName)"
                            #    Write-Host "DEST: $dest_path"
                            #    Log-Message "[!] [$target] Error copying file: $($file.FullName)" $false "red"
                            #}
                        }


                    }
                }
            }
        }
    }
}

function Build-Command-Script ($initial_command, $output){
    $command = $initial_command -replace ("#FILEPATH#", $output)
    $command_bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $commandb64 = [Convert]::ToBase64String($command_bytes)
    $command_final = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $commandb64
    return $command_final
}

function Execute-WMI-Command ($command, $target){
    $command_start = Invoke-WmiMethod -ComputerName $target -Credential $global_configuration.credential -Class Win32_Process -Name Create -ArgumentList "$command_final"
    return $command_start
}

function Run-Commands ($target, $current_evidence_dir) {
    # Responsible for executing commands on target host and collecting the output
    # Commands are encoded into b64 and sent to the target via WMI process creation
    # We send all of the commands simultaneously then iterate over the expected file-names waiting for results (presuming we do not get a failure to create the process from WMI)
    # We set a limit on this to ensure we are not waiting for a 'broken' process
    $target_files = @{}
    $copy_location = @{}
    $process_ids = @{}
    ForEach ($item in $global_configuration.config.commands){
        $obj_names = $item.psobject.Properties.Name
        ForEach ($category in $obj_names){
            Log-Message "[+] [$target] Collecting: $category"
            $cmd_evidence_dir = $current_evidence_dir + "\" + $item.$category.category + "\" + $category
            Create-Directory $cmd_evidence_dir
            $final_name = $($item.$category.output)
            $stamp = (Get-Date).toString("HH:mm:ss") -replace (":","_")
            # Assuming C$ is accessible drive here
            $tmp_name = "\\$target\C$\Windows\temp\$stamp`_$($item.$category.output)"
            $command_final = Build-Command-Script $item.$category.command $tmp_name
            $command_start = Execute-WMI-Command $command_final $target
            if ($command_start.ReturnValue -eq 0){
                $target_files[$category] = $tmp_name
                $copy_location[$category] = $cmd_evidence_dir + "\" + $final_name
                $process_ids[$category] = $command_start.ProcessId

            }
        }
    }
    # TODO - ProcID checks to determine if still running or not.
    Log-Message "[*] [$target] Waiting for Output..."
    $loops = 0
    while ($true){
        if ($target_files.Count -eq 0){
            break
        }
        $removals = New-Object -TypeName "System.Collections.ArrayList"
        Start-Sleep 3
        ForEach ($i in $target_files.GetEnumerator() ){
            try {
                if (Test-Path $i.Value){
                    Copy-Item $i.Value $copy_location[$i.Name] -Force
                    $removals.Add($i.Name) | Out-Null
                }
            } catch {
            }
        }
        $loops += 1
        ForEach ($removed in $removals){
            $target_files.Remove($removed)
        }
        if ($loops -ge 10 -and $target_files.Count -ne 0){
            Log-Message "[!] Unable to find output file for the following modules:" $true
            ForEach ($i in $target_files.GetEnumerator() ){
                Log-Message "[+] $($i.Name)"
            }
            break
        }
    }
}

function Get-Registry ($target, $current_evidence_dir) {
    # There are typically 3 classic ways to read the registry of a remote device:
    # 1 - InvokeCommand with classic PowerShell - requires WinRM, basically a non-starter for most endpoints
    # 2 - WMI Built-Ins - Doable as long as WMI is available (mostly it is), but limited.
    # 3 - Remote Registry Service - This is typically disabled by default but we could check the state via WMI, enable then re-disable once we are done collecting data.
    # 4 - We could take a similar approach as for running commands - package each registry check into a command, pass it via WMI and check for an output file - this will be the easiest and most flexible way.
    # By default, we will take option 4 - it allows for the most flexibility when specifying paths to check (recursiveness, wildcards, etc via Get-ChildItem).

    $HKEY_CLASSES_ROOT = 2147483648
    $HKEY_CURRENT_USER = 2147483649
    $HKEY_LOCAL_MACHINE = 2147483650
    $HKEY_USERS = 2147483651
    $HKEY_CURRENT_CONFIG = 2147483653
    $HKEY_DYN_DATA = 2147483654
    ForEach ($item in $global_configuration.config.registry)
    {
        $obj_names = $item.psobject.Properties.Name
        ForEach ($category in $obj_names)
        {
            Log-Message "[+] [$target] Collecting: $category"
            $temp_evidence_dir = $current_evidence_dir + "\" + $category
            $reg_paths = $item.$category.paths
            $recursive_flag = $item.$category.recursive
            $key_filters = $item.$category.keys
            ForEach ($path in $reg_paths){
                if ($path.StartsWith("HKLM") -or $path.StartsWith("HKEY_LOCAL_MACHINE")){
                    $hive = $HKEY_LOCAL_MACHINE
                } elseif ($path.StartsWith("HKU") -or $path.StartsWith("HKEY_USERS")){
                    $hive = $HKEY_USERS
                } elseif ($path.StartsWith("HKCU") -or $path.StartsWith("HKEY_CURRENT_USER")){
                    $hive = $HKEY_CURRENT_USER
                } elseif ($path.StartsWith("HKCR") -or $path.StartsWith("HKEY_CLASSES_ROOT")){
                    $hive = $HKEY_CLASSES_ROOT
                } else {
                    Log-Message "[!] Unable to find appropriate hive for key: $path"
                }
                #Write-Host $path

                #$data = Invoke-WMIMethod -ComputerName $target -Namespace root\default -Class stdregprov -Name enumvalues @($hive, $path)
                #ForEach ($object in $data){
                    #Write-Host $object.sNames
                #}
                if ($recursive_flag){
                    $command = "Get-ChildItem -Path `"Registry::$path`" -Recurse"
                } else {
                    $command = "Get-ChildItem -Path `"Registry::$path`" "
                }
                $command_final = Build-Command-Script $command $tmp_name

            }
        }
    }
}


function Get-Credentials {
    $Credential = $host.ui.PromptForCredential("PowerHaul Credential Entry", "Please enter username and password.", "", "NetBiosUserName")
    #Write-Host $Credential.UserName
    #Write-Host $Credential.GetNetworkCredential().Password
    return $Credential
}


function Create-Shadow ($target){
    Log-Message "[+] [$target] Creating Shadow"
    $shadow_start = Invoke-WmiMethod -ComputerName $target -Credential $global_configuration.credential -Class Win32_Process -Name Create -ArgumentList "$new_shadow_command"
    $loops = 0
    while ($true) {
        Start-Sleep 3
        $file = Get-WMIObject -Query "Select * from CIM_Datafile Where Name = '$shadowcopy_output_status_file'" -ComputerName $target -Credential $global_configuration.credential
        if ($file){
            $data = Get-Content "\\$target\C$\Windows\Temp\$shadowcopy_output_status_file.txt"
            $split = $data -split ":"
            if ($split[0] -eq "SUCCESS") {
                return 0
            } else {
                return 1
            }
        }
        else {
            $loops += 1
        }
        if ($loops -ge 10){
            return 1
        }
    }
}

function Delete-Shadow ($target){
    Log-Message "[+] [$target] Deleting Shadow"
    $shadow_start = Invoke-WmiMethod -ComputerName $target -Credential $global_configuration.credential -Class Win32_Process -Name Create -ArgumentList "$remove_shadow_command"
}

function Main{
    Log-Message "
        ____                          __  __            __
       / __ \____ _      _____  _____/ / / /___ ___  __/ /
      / /_/ / __ \ | /| / / _ \/ ___/ /_/ / __  `/ / / / /
     / ____/ /_/ / |/ |/ /  __/ /  / __  / /_/ / /_/ / /
    /_/    \____/|__/|__/\___/_/  /_/ /_/\__,_/\__,_/_/
    " -color "Green"
    Log-Message "    PowerHaul - https://github.com/joeavanzato/powerhaul" -color "Green"
    Log-Message "    Happy Hunting!" -color "Green"
    Write-Host ""
    Create-Directory $evidence_dir | Out-Null
    if ($creds){
        $global_configuration.credential = Get-Credentials
    }
    #$global_configuration.credential = Get-Credentials
    $configuration_data = Get-Configuration
    $computer_targets = Get-Targets
    $global_configuration.config = $configuration_data
    $global_configuration.finished = 0
    Start-Jobs $computer_targets
    Log-Message "[!] Done! Evidence Directory: $evidence_dir"

    #$fns = Get-ChildItem function: | Where-Object { $_.Name -like "Create-Shadow" }
    #Write-Host $fns.ScriptBlock

}

Main