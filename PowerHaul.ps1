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
        Run-Commands $target $current_evidence_dir
        Delete-Shadow $target
    }
}

function Get-Files ($target, $current_evidence_dir, $root_replace) {
    # TODO - Make user dir for any path which falls under C:\users\ and use as appropriate as base evidence directory
    ForEach ($item in $global_configuration.config.files){
        $obj_names = $item.psobject.Properties.Name
        ForEach ($category in $obj_names){
            Log-Message "[+] [$target] Collecting: $category"
            $file_evidence_dir = $current_evidence_dir + "\" + $category
            ForEach ($path in $item.$category.paths){
                if ($root_replace){
                    $tmp_path = $path -replace ("%HOMEDRIVE%", "\\$target\C$\$shadowcopy_name")
                } else {
                    $tmp_path = $path -replace ("%HOMEDRIVE%", "\\$target\C$")
                }
                if ($global_configuration.credential){
                    Write-Host "CREDS"
                    # TODO - possibly map drive but probably not required in most situations if access is already present.
                }

                try {
                    $file_list = New-Object -TypeName "System.Collections.ArrayList"
                    ForEach ($filter in $item.$category.filter){
                        $files = $null
                        if ($item.$category.recursive){
                            $files = Get-ChildItem -Path "$tmp_path" -Recurse -Filter $filter -Force -ErrorVariable FailedItems -ErrorAction SilentlyContinue | Where {! $_.PSIsContainer }
                        } else {
                            $files = Get-ChildItem -Path "$tmp_path" -Filter $filter -Force -ErrorVariable FailedItems -ErrorAction SilentlyContinue | Where {! $_.PSIsContainer }
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
                ForEach ($file in $file_list){
                    # If the file we are attempting to copy exists under a specific user directory (Jumplists, etc) then we will store it under the relevant users name - $evidence_dir\jumplists\$USERNAME\$file
                    try {
                        if ($($file.FullName) -match ".*\\users\\(?<user>[^\\]*)\\.*"){
                            $tmp_user_evidence_dir = $file_evidence_dir + "\" + $Matches.user
                            Create-Directory $tmp_user_evidence_dir
                            Copy-Item "$($file.FullName)" "$tmp_user_evidence_dir" -Force
                        } else {
                            Copy-Item "$($file.FullName)" "$file_evidence_dir" -Force
                        }
                    } catch{
                        Log-Message "[!] Error copying file: $($file.FullName)" $true
                    }
                }
            }
        }
    }
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
            $cmd_evidence_dir = $current_evidence_dir + "\" + $category
            Create-Directory $cmd_evidence_dir
            $final_name = $($item.$category.output)
            $stamp = (Get-Date).toString("HH:mm:ss") -replace (":","_")
            $tmp_name = "\\$target\C$\Windows\temp\$stamp`_$($item.$category.output)"
            $command = $item.$category.command -replace ("#FILEPATH#", $tmp_name)
            $command_bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
            $commandb64 = [Convert]::ToBase64String($command_bytes)
            $command_final = "powershell.exe -NoLogo -NonInteractive -ExecutionPolicy Unrestricted -WindowStyle Hidden -EncodedCommand " + $commandb64
            $command_start = Invoke-WmiMethod -ComputerName $target -Credential $global_configuration.credential -Class Win32_Process -Name Create -ArgumentList "$command_final"
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

}

Main