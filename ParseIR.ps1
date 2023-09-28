

# The successful file copies csv is used as a basis for telling ParseIR which files should be parsed by which utility
# The 'name' of  the JSON object is used to match the 'parser' configuration in the evidence collection JSON
# In Evidence Collection directives, parser can be a comma-delimited list of values - but still string, not array.
# A 'parser' can be any type of script invoked by cmd.exe \c - powershell scripts, etc.

[CmdletBinding()]
param
(
	[Parameter(Mandatory = $false, HelpMessage = 'The fully-qualified file-path where evidence is stored, defaults to $PSScriptRoot\evidence')]
	[string]$evidence_dir = "$PSScriptRoot\evidence",

	[Parameter(Mandatory = $false, HelpMessage = 'The fully-qualified directory where parsed evidence will be stored, defaults to $PSScriptRoot\parsed_evidence')]
	[string]$parsed_evidence_dir = "$PSScriptRoot\parsed_evidence",

	[Parameter(Mandatory = $false, HelpMessage = 'The fully-qualified file-path for the configuration file, defaults to $PSScriptRoot\parse_config.json')]
	[string]$config = "$PSScriptRoot\parsing_config.json",

	[Parameter(Mandatory = $false, HelpMessage = 'Tell RetrievIR to ignore missing dependencies.')]
	[switch]$ignoremissing,

	[Parameter(Mandatory = $false, HelpMessage = 'The fully-qualified directory where third-party parsers are/will be stored - defaults to $PSScriptRoot\utils_dir')]
	[string]$utilities_dir = "$PSScriptRoot\utilities"
)

function Get-Configuration {
    if (-not (Test-Path $config)){
        Log-Message "Could not find specified configuration path: $config" $true
        Log-Message "[*] Please double check the specified file exists!"
        Log-Message "[!] Exiting..."
        exit
    }

    try {
        $data = Get-Content -Path $config -Raw | ConvertFrom-Json
    } catch {
        Log-Message "[!] Error reading specified configuration path" $true
        Log-Message "[!] Exiting..."
        exit
    }
    return $data
}

function Validate-Configuration($data) {
    $error_count = 0
    ForEach ($object in $data){
        $object_name = $object.psobject.Properties.Name
        ForEach ($name in $object_name){
            if (-not $object.$name.name){
                Log-Message "[!] Config object missing name!" $false "red"
                $error_count +=1
                Log-Message $object
            }
            if (-not $object.$name.evidence_type){
                Log-Message "[!] Config object missing evidence_type!" $false "red"
                $error_count +=1
                Log-Message $object
            }
            if (-not $object.$name.executable){
                Log-Message "[!] Config object missing parser executable!" $false "red"
                $error_count +=1
                Log-Message $object
            }
            if (-not $object.$name.cmdline){
                Log-Message "[!] Config object missing parser commandline!" $false "red"
                $error_count +=1
                Log-Message $object
            }
            if (-not $object.$name.url){
                Log-Message "[!] Config object missing binary url!" $false "red"
                $error_count +=1
                Log-Message $object
            }
            if (-not $object.$name.if_missing){
                Log-Message "[!] Config object missing 'if_missing'!" $false "red"
                $error_count +=1
                Log-Message $object
            }
            if (-not $object.$name.dl_type){
                Log-Message "[!] Config object missing 'dl_type'!" $false "red"
                $error_count +=1
                Log-Message $object
            }
            if (-not $object.$name.operates_on){
                Log-Message "[!] Config object missing 'operates_on'!" $false "red"
                $error_count +=1
                Log-Message $object
            }
        }
    }
    if ($error_count -ne 0){
        Log-Message "[!] Configuration Errors Detected: $error_count" $false "red"
        Log-Message "[!] Please rectify before continuing!" $false "red"
        exit
    } else {
        Log-Message "[!] Configuration Validated!"
    }
}

function Log-Message ($msg, $error, $color){
    $timestamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $log_path = "$PSScriptRoot\ParseIR.log"
    if (-not $color){
        $color = "White"
    }
    if ($error){
        Write-Warning $msg
    } else {
        Write-Host $msg -ForegroundColor $color
    }
    Add-Content -Path $log_path -Value "$timestamp - $msg"
}

function Get-Successful-Copy-File {
    $output_path = $evidence_dir+"\successful_file_copies.csv"
    Log-Message "[!] Reading File Copy CSV: $output_path"
    try {
        $data = Import-CSV -Path $output_path
    } catch {
        Log-Message "[!] Fatal error parsing file copies CSV!" $false "red"
        exit
    }
    return $data
}

function Create-Directory ($dir) {
    if (Test-Path $dir){
        return
    }
    try {
        New-Item -Path $dir -ItemType Directory | Out-Null
        Log-Message "[!] Directory Created: $dir" -quiet $true
    }catch{
        Log-Message "[!] Could not create directory: $dir" $true
        exit
    }
}

function Download-Binary($url, $destination_dir, $final_name, $type, $parse_type) {
    Log-Message "[+] Downloading $final_name from $url"
    if ($type -eq "zip"){
        $zip_path = "$destination_dir\$final_name.zip"
        Invoke-WebRequest "$url" -OutFile $zip_path
        Expand-Archive -Path $zip_path -DestinationPath "$destination_dir\$final_name" -Force
        Remove-Item -Path $zip_path
    } elseif ($type -eq "exe"){
        $exe_path = "$destination_dir\$final_name"
        Invoke-WebRequest "$url" -OutFile $exe_path
    }
    if ($parse_type -eq "standalone"){
        Start-Sleep 1
        try {
            Move-Item -Path "$destination_dir\$final_name" -Destination "$destination_dir\standalone"
        } catch {
            Log-Message "[!] Unable to move directory/item to standalones!"
        }
    }
}

function Check-Tools ($config_data){
    if (-not (Test-Path $utilities_dir)){
        Create-Directory $utilities_dir
    }
    $util_contents = Get-ChildItem -Path $utilities_dir -Recurse | Where {! $_.PSIsContainer }
    if ($util_contents.GetType().Name -eq "String"){
        $util_contents = @($util_contents)
    }
    ForEach ($object in $config_data)
    {
        $object_name = $object.psobject.Properties.Name
        ForEach ($name in $object_name) {
            $exe_name = $object.$name.executable
            $found = $false
            ForEach ($file in $util_contents){
                if ($file.Name -eq $exe_name){
                    $found = $true
                    break
                }
            }
            if (-not ($found) -and ($object.$name.if_missing -eq "download")){
                Download-Binary $object.$name.url $utilities_dir $object.$name.executable $object.$name.dl_type $object.$name.type
            } elseif (-not ($found) -and -not ($object.$name.type -eq "native")){
                Log-Message "[!] Missing Binary without downloading: $exe_name"
            } else {
                Log-Message "[!] Found Binary: $exe_name"
            }
        }
    }
    $parser_locations = @{}
    $util_contents = Get-ChildItem -Path $utilities_dir -Recurse | Where {! $_.PSIsContainer }
    if ($util_contents.GetType().Name -eq "String"){
        $util_contents = @($util_contents)
    }
    ForEach ($object in $config_data) {
        $object_name = $object.psobject.Properties.Name
        ForEach ($name in $object_name) {
            $exe_name = $object.$name.executable
            ForEach ($file in $util_contents){
                if ($file.Name -eq $exe_name){
                    $parser_locations[$name] = $file.FullName
                }
            }
        }
    }
    return $parser_locations

}

function Start-Processing ($parse_config, $file_data, $exe_locations){
    if (-not (Test-Path $parsed_evidence_dir)){
        Create-Directory $parsed_evidence_dir
    }
    $files_parsed = New-Object -TypeName 'System.Collections.ArrayList'
    $dirs_parsed = New-Object -TypeName 'System.Collections.ArrayList'
    ForEach ($record in $file_data){
        #continue
        # TODO - Remove Above
        if ($record.Parser -eq "N/A"){
            # Skip parsing files that don't have an assigned parser in their output
            continue
        }
        if ($record.Parser -match ".*,.*"){
            $parsers = $record.Parser -split ","
        } else {
            $parsers = @($record.Parser)
        }
        ForEach ($parser in $parsers){
            if (-not ($parse_config.$parser)){
                Log-Message "No Available Parser Configured for type: $parser" $false "Red"
                continue
            }
            $parse_object = $parse_config.$($parser)
            if ($parse_object.type -eq "standalone"){
                continue
            }
            $pass = $true
            $file_basename = Split-Path -Leaf $record.FileName
            if ($parse_object.file_filter[0] -eq "*"){
                $pass = $false
            }else{
                ForEach ($filter in $parse_object.file_filter){
                    if ($file_basename -like $filter){
                        $pass = $false
                    }
                }
            }
            if ($pass){
                continue
            }
            $base_evidence_path = $parsed_evidence_dir + "\" + $record.Computer
            #Write-Host $base_evidence_path
            #if (-not (Test-Path ))
            if ($parse_object.operates_on -eq "dir"){
                $source_target = Split-Path -Parent $record.FileName
                if ($source_target -in $dirs_parsed){
                    continue
                }
                $dirs_parsed.Add($source_target) | Out-Null

            } elseif ($parse_object.operates_on -eq "file") {
                $source_target = $record.FileName
                if ($source_target -in $files_parsed){
                    continue
                }
                $files_parsed.Add($source_target) | Out-Null
            }
            Parse $parse_object $record $base_evidence_path $source_target $exe_locations[$parser]
        }
    }


    #Standalone Parsers
    ForEach ($object in $parse_config) {
        $object_name = $object.psobject.Properties.Name
        ForEach ($name in $object_name) {
            $exe_name = $object.$name.executable
            $type = $object.$name.type
            if($type -ne "standalone"){
                continue
            }
            Execute-Standalone-Parser $object.$name $exe_locations[$name]
        }
    }
}

function Execute-Standalone-Parser ($parser, $bin_loc){
    $commandline = $parser.cmdline
    if ($commandline -eq "N/A"){
        return
    }
    if ($commandline -match ".*#EVIDENCE_DIR#.*"){
        $commandline = $commandline -replace ("#EVIDENCE_DIR#", "`"$evidence_dir`"")
    }
    if ($commandline -match ".*#PARSER#.*"){
        $commandline = $commandline -replace ("#PARSER#", "`"$bin_loc`"")
    }
    if ($commandline -match ".*#PARSED_EVIDENCE_DIR#.*"){
        $commandline = $commandline -replace ("#PARSED_EVIDENCE_DIR#", "`"$parsed_evidence_dir`"")
    }
    Log-Message "[+] Executing: $commandline"
    & powershell.exe $commandline

}

function Parse ($parser, $record, $base_evidence_dir, $target, $exe_full_path){
    Log-Message "[+] Parsing: $($record.FileName)"
    $tmp_evidence_storage = $base_evidence_dir + "\" + $parser.evidence_type
    Create-Directory $tmp_evidence_storage
    $current_location = Get-Location
    if ($record.User -ne "N/A"){
        $tmp_evidence_storage += "\$($record.User)"
        Create-Directory $tmp_evidence_storage
    }
    $commandline = $parser.cmdline
    if ($commandline -match ".*#SOURCE_FILE#.*"){
        $commandline = $commandline -replace ("#SOURCE_FILE#", "`"$target`"")
    } elseif ($commandline -match ".*#SOURCE_DIR#.*"){
        $commandline = $commandline -replace ("#SOURCE_DIR#", "`"$target`"")
    }
    if ($exe_full_path){
        $commandline = $commandline -replace ("#PARSER#", "`"$exe_full_path`"")
    } else {
        $commandline = $commandline -replace ("#PARSER#", "`"$($parser.executable)`"")
    }
    $tmp_evidence_storage = $tmp_evidence_storage.TrimEnd("\")
    if ($commandline -match ".*#DESTINATION_DIR#.*"){
        $commandline = $commandline -replace ("#DESTINATION_DIR#", "`"$tmp_evidence_storage`"")
    } elseif ($commandline -match ".*#DESTINATION_FILE#.*"){
        $commandline = $commandline -replace ("#DESTINATION_FILE#", "`"$tmp_evidence_storage`"")
    }
    #Write-Host $commandline
    Log-Message "[+] Executing: $commandline"
    if ($parser.type -eq "inline"){
        & cmd.exe /c $commandline
    } elseif ($parser.type -eq "native"){
        Invoke-Expression $commandline
    }
    #& cmd.exe /c $commandline
    #Start-Job {cmd.exe /c $commandline}


}

function Main{
    Log-Message "[!] Starting Evidence Parsing..."
    Log-Message "[+] Using Configuration: $config"
    Log-Message "[+] Using Evidence Directory: $evidence_dir"
    Log-Message "[+] Reading Configuration Data..."
    $config_data = Get-Configuration
    Validate-Configuration $config_data
    $file_copies = Get-Successful-Copy-File
    $exe_locations = Check-Tools $config_data
    Start-Processing $config_data $file_copies $exe_locations
}

Main