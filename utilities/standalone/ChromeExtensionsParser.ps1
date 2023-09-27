
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true, HelpMessage = 'The fully-qualified file-path where evidence is stored.')]
	[string]$base_evidence_dir,

	[Parameter(Mandatory = $true, HelpMessage = 'The fully-qualified file-path where parsed evidence is stored.')]
	[string]$parsed_evidence_dir
)


$chrome_extensions = New-Object -TypeName 'System.Collections.ArrayList'
$targets = Get-ChildItem $base_evidence_dir | Where { $_.PSIsContainer }
$parser_storage_dir = "Browser"
$output_filename = "ChromeExtensions.csv"

ForEach ($target in $targets){
    $extension_dirs = Get-ChildItem -Path "$base_evidence_dir\$target\Browsers\ChromeUserData\*\User Data\Default\Extensions"
    $tmp_evidence_dir = "$parsed_evidence_dir\$target\$parser_storage_dir"
    $output_file ="$tmp_evidence_dir\$output_filename"
    if (-not (Test-Path $tmp_evidence_dir)){
        New-Item -Path $tmp_evidence_dir -ItemType Directory | Out-Null
    }
    ForEach ($dir in $extension_dirs){
        if ($dir -match ".*\\ChromeUserData\\(?<user>[^\\]*)\\.*") {
            $user = $Matches.user
        } else {
            $user = "N/A"
        }
        $extension_dirs = Get-ChildItem $dir | Where { $_.PSIsContainer }
        ForEach ($extension in $extension_dirs){
            $manifest = Get-ChildItem -Path $extension.FullName -filter manifest.json -Recurse
            try {
                $manifest_json = Get-Content -Path $manifest.FullName -Raw | ConvertFrom-Json
            } catch {
                Write-Host "[!] Error Reading Chrome Extension Manifest: $($manifest.FullName)"
                continue
            }
            if ($manifest_json.app.background.scripts){
                $background_scripts = $manifest_json.app.background.scripts -Join ","
            } else {
                $background_scripts = ""
            }
            if ($manifest_json.background.service_worker){
                $service_worker = $manifest_json.background.service_worker
            } else {
                $service_worker = ""
            }
            if ($manifest_json.manifest_version){
                $manifest_version = $manifest_json.manifest_version
            } else {
                $manifest_version = ""
            }
            if ($manifest_json.name){
                $name = $manifest_json.name
            } else {
                $name = ""
            }
            if ($manifest_json.description){
                $description = $manifest_json.description
            } else {
                $description = ""
            }
            if ($manifest_json.oauth2.auto_approve){
                $oauth_autoapprove = $manifest_json.oauth2.auto_approve
            } else {
                $oauth_autoapprove = ""
            }
            if ($manifest_json.oauth2.client_id){
                $oauth_client_id = $manifest_json.oauth2.client_id
            } else {
                $oauth_client_id = ""
            }
            if ($manifest_json.oauth2.scopes){
                $oauth_scopes = $manifest_json.oauth2.scopes -Join ","
            } else {
                $oauth_scopes = ""
            }
            if ($manifest_json.permissions){
                $permissions = $manifest_json.permissions -Join ","
            } else {
                $permissions = ""
            }
            if ($manifest_json.host_permissions){
                $host_permissions = $manifest_json.host_permissions -Join ","
            } else {
                $host_permissions = ""
            }
            if ($manifest_json.update_url){
                $update_url = $manifest_json.update_url
            } else {
                $update_url = ""
            }
            if ($manifest_json.version){
                $version = $manifest_json.version
            } else {
                $version = ""
            }
            $tmp = [PSCustomObject]@{
                dirname = $extension
                evidence_dir = $extension.FullName
                user = $user
                computer = $target
                background_scripts = $background_scripts
                manifest_version = $manifest_version
                name = $name
                description = $description
                oauth_autoapprove = $oauth_autoapprove
                oauth_client_id = $oauth_client_id
                oauth_scopes = $oauth_scopes
                permissions = $permissions
                host_permissions = $host_permissions
                update_url = $update_url
                version = $version
            }
            $chrome_extensions.Add($tmp) | Out-Null
        }
    }
    $chrome_extensions | Export-Csv -NoTypeInformation -Path $output_file

}