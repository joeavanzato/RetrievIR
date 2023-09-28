
[CmdletBinding()]
param
(
	[Parameter(Mandatory = $true, HelpMessage = 'The fully-qualified file-path where evidence is stored.')]
	[string]$base_evidence_dir,

	[Parameter(Mandatory = $true, HelpMessage = 'The fully-qualified file-path where parsed evidence is stored.')]
	[string]$parsed_evidence_dir
)

### START SECTION: EXTENSION PARSING
function Parse-Extension-Manifest ($manifest_json, $extension, $user, $target, $chrome_extensions){
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

function Find-Extension-Manifest ($target){
    $browsers = @{
        "ChromeUserData" = "Chrome"
        "EdgeUserData" = "Edge"
    }
    foreach ($key in $browsers.Keys) {
        $bwsr = $browsers[$key]

        $chrome_extensions = New-Object -TypeName 'System.Collections.ArrayList'
        $parser_storage_dir = "Browser"
        $output_filename = "$bwsr`Extensions.csv"

        try {
            $extension_dirs = Get-ChildItem -Path "$base_evidence_dir\$target\Browsers\$key\*\User Data\Default\Extensions"
        }
        catch {
            Write-Host "[!] [$target] Could not find Browsers\$key\*\User Data\Default\Extensions Directory!"
            continue
        }
        $tmp_evidence_dir = "$parsed_evidence_dir\$target\$parser_storage_dir"
        $output_file = "$tmp_evidence_dir\$output_filename"
        if (-not(Test-Path $tmp_evidence_dir)) {
            New-Item -Path $tmp_evidence_dir -ItemType Directory | Out-Null
        }
        ForEach ($dir in $extension_dirs) {
            if ($dir -match ".*\\$key\\(?<user>[^\\]*)\\.*") {
                $user = $Matches.user
            }
            else {
                $user = "N/A"
            }
            $extension_dirs = Get-ChildItem $dir | Where { $_.PSIsContainer }
            ForEach ($extension in $extension_dirs) {
                $manifest = Get-ChildItem -Path $extension.FullName -filter manifest.json -Recurse
                try {
                    $manifest_json = Get-Content -Path $manifest.FullName -Raw | ConvertFrom-Json
                }
                catch {
                    Write-Host "[!] Error Reading Extension Manifest: $( $manifest.FullName )"
                    continue
                }
                Parse-Extension-Manifest $manifest_json $extension $user $target $chrome_extensions

            }
        }
        $chrome_extensions | Export-Csv -NoTypeInformation -Path $output_file -Append
    }
}
### END SECTION: EXTENSION PARSING

### START SECTION: HISTORY PARSING
function Parse-History ($target){
    $parser_storage_dir = "Browser"
    $tmp_evidence_dir = "$parsed_evidence_dir\$target\$parser_storage_dir"

    $browsers = @{
        "ChromeUserData" = "Chrome"
        "EdgeUserData" = "Edge"
    }

    foreach ($key in $browsers.Keys) {
        $bwsr = $browsers[$key]


        $url_table_objects = New-Object -TypeName 'System.Collections.ArrayList'
        $url_output_filename = "$bwsr`History_URLs.csv"
        $url_output_file = "$tmp_evidence_dir\$url_output_filename"

        $downloads_table_objects = New-Object -TypeName 'System.Collections.ArrayList'
        $downloads_output_filename = "$bwsr`History_Downloads.csv"
        $downloads_output_file = "$tmp_evidence_dir\$downloads_output_filename"

        $keyword_search_table_objects = New-Object -TypeName 'System.Collections.ArrayList'
        $keywords_output_filename = "$bwsr`History_KeywordTerms.csv"
        $keywords_output_file = "$tmp_evidence_dir\$keywords_output_filename"

        $visits_table_objects = New-Object -TypeName 'System.Collections.ArrayList'
        $visits_output_filename = "$bwsr`History_Visits.csv"
        $visits_output_file = "$tmp_evidence_dir\$visits_output_filename"

        if (-not(Test-Path $tmp_evidence_dir)) {
            New-Item -Path $tmp_evidence_dir -ItemType Directory | Out-Null
        }
        try {
            $sqldll = Get-ChildItem -Path $PSScriptRoot -Filter "System.Data.SQLite.dll" -Recurse | Where { !$_.PSIsContainer }
            if (-not$sqldll)
            {
                Write-Host "[!] Could not find System.Data.SQLite.dll!"
                return
            }
        }
        catch {
            Write-Host "[!] Could not find System.Data.SQLite.dll!"
            return
        }
        $sqlite_dll_location = $sqldll.FullName
        [Reflection.Assembly]::LoadFile($sqlite_dll_location) | Out-Null
        try {
            $history_files = Get-ChildItem -Path "$base_evidence_dir\$target\Browsers\$key\*\User Data\*\History"
        }
        catch {
            Write-Host "[!] [$target] Could not find Browsers\$key\*\User Data\Default\History!"
            return
        }

        if ($history_files.GetType().Name -eq "String") {
            $history_files = @($history_files)
        }
        ForEach ($file in $history_files) {
            if ($file.FullName -match ".*\\$key\\(?<user>[^\\]*)\\.*") {
                $user = $Matches.user
            }
            else {
                $user = "N/A"
            }
            $queries = @{
                "urls" = "SELECT * from urls"
            }
            $dbString = [string]::Format("data source={0}", $file.FullName)
            $dbConnection = New-Object System.Data.SQLite.SQLiteConnection
            $dbConnection.ConnectionString = $dbString
            $dbConnection.open()

            Parse-URLs-Table $target $user $dbConnection $url_table_objects
            Parse-Downloads-Table $target $user $dbConnection $downloads_table_objects
            Parse-Keyword-Search-Terms-Table $target $user $dbConnection $keyword_search_table_objects
            Parse-Visits-Table $target $user $dbConnection $visits_table_objects

            $dbConnection.Close()
        }
        $url_table_objects | Export-Csv -NoTypeInformation -Path $url_output_file -Append
        $downloads_table_objects | Export-Csv -NoTypeInformation -Path $downloads_output_file -Append
        $keyword_search_table_objects | Export-Csv -NoTypeInformation -Path $keywords_output_file -Append
        $visits_table_objects | Export-Csv -NoTypeInformation -Path $visits_output_file -Append

    }
}

function Parse-Visits-Table ($target, $user, $dbConnection, $visits_table_objects){
    $dbCmd = $dbConnection.CreateCommand()
    # Chrome has 'external_referrer_url, edge does not I guess?
    $dbCmd.Commandtext = "SELECT visits.id,urls.url,title,visit_time,from_visit,visit_duration FROM visits INNER JOIN urls ON visits.url = urls.id"
    $dbCmd.CommandType = [System.Data.CommandType]::Text
    $dbReader = $dbCmd.ExecuteReader()
    #$dbReader.GetValues()
    while($dbReader.HasRows) {
        if($dbReader.Read())
        {
            $last_visit_utc = ([datetime] '1970-01-01Z').ToUniversalTime()
            $last_visit_time = $dbReader["visit_time"]
            $last_visit_time = $last_visit_time / 1000000
            $last_visit_time = $last_visit_time - 11644473600
            $visit_time = $last_visit_utc.AddSeconds($last_visit_time)
            $tmp = [PSCustomObject]@{
                computer = $target
                user = $user
                id = $dbReader["id"]
                url = $dbReader["url"]
                title = $dbReader["title"]
                from_visit = $dbReader["from_visit"]
                visit_duration = $dbReader["visit_duration"]
                external_referrer_url = $dbReader["external_referrer_url"]
                visit_time = $visit_time
            }
            $visits_table_objects.Add($tmp) | Out-Null
        }
    }
    $dbReader.Close()
}

function Parse-URLs-Table ($target, $user, $dbConnection, $url_table_objects){
    $dbCmd = $dbConnection.CreateCommand()
    $dbCmd.Commandtext = "SELECT * from urls"
    $dbCmd.CommandType = [System.Data.CommandType]::Text
    $dbReader = $dbCmd.ExecuteReader()
    #$dbReader.GetValues()
    while($dbReader.HasRows) {
        if($dbReader.Read())
        {
            $last_visit_utc = ([datetime] '1970-01-01Z').ToUniversalTime()
            $last_visit_time = $dbReader["last_visit_time"]
            $last_visit_time = $last_visit_time / 1000000
            $last_visit_time = $last_visit_time - 11644473600
            $last_visit_utc = $last_visit_utc.AddSeconds($last_visit_time)
            $tmp = [PSCustomObject]@{
                computer = $target
                user = $user
                id = $dbReader["id"]
                url = $dbReader["url"]
                title = $dbReader["title"]
                visit_count = $dbReader["visit_count"]
                typed_count = $dbReader["typed_count"]
                last_visit_time = $last_visit_utc
            }
            $url_table_objects.Add($tmp) | Out-Null
        }
    }
    $dbReader.Close()
}

function Parse-Keyword-Search-Terms-Table ($target, $user, $dbConnection, $keyword_search_table_objects){
    $dbCmd = $dbConnection.CreateCommand()
    $dbCmd.Commandtext = "SELECT keyword_id, url_id, term, url, title, last_visit_time FROM keyword_search_terms INNER JOIN urls ON keyword_search_terms.url_id = urls.id"
    $dbCmd.CommandType = [System.Data.CommandType]::Text
    $dbReader = $dbCmd.ExecuteReader()
    #$dbReader.GetValues()
    while($dbReader.HasRows) {
        if($dbReader.Read())
        {
            $last_visit_utc = ([datetime] '1970-01-01Z').ToUniversalTime()
            $last_visit_time = $dbReader["last_visit_time"]
            $last_visit_time = $last_visit_time / 1000000
            $last_visit_time = $last_visit_time - 11644473600
            $last_visit_utc = $last_visit_utc.AddSeconds($last_visit_time)
            $tmp = [PSCustomObject]@{
                computer = $target
                user = $user
                keyword_id = $dbReader["keyword_id"]
                url_id = $dbReader["url_id"]
                term = $dbReader["term"]
                url = $dbReader["url"]
                title = $dbReader["title"]
                last_visit_time = $last_visit_utc
            }
            $keyword_search_table_objects.Add($tmp) | Out-Null
        }
    }
    $dbReader.Close()
}

function Parse-Downloads-Table ($target, $user, $dbConnection, $downloads_table_objects){
    $dbCmd = $dbConnection.CreateCommand()
    $dbCmd.Commandtext = "SELECT * from downloads"
    $dbCmd.CommandType = [System.Data.CommandType]::Text
    $dbReader = $dbCmd.ExecuteReader()
    #$dbReader.GetValues()
    while($dbReader.HasRows) {
        if($dbReader.Read())
        {
            $start_time_utc = ([datetime] '1970-01-01Z').ToUniversalTime()
            $start_time = $dbReader["start_time"]
            $start_time = $start_time / 1000000
            $start_time = $start_time - 11644473600
            $start_time_utc = $start_time_utc.AddSeconds($start_time)
            $tmp = [PSCustomObject]@{
                computer = $target
                user = $user
                id = $dbReader["id"]
                guid = $dbReader["guid"]
                current_path = $dbReader["current_path"]
                target_path = $dbReader["target_path"]
                start_time = $start_time_utc
                received_bytes = $dbReader["received_bytes"]
                danger_type = $dbReader["danger_type"]
                opened = $dbReader["opened"]
                referrer = $dbReader["referrer"]
                tab_url = $dbReader["tab_url"]
                tab_referrer_url = $dbReader["tab_referrer_url"]
                last_modified = $dbReader["last_modified"]
                mime_type = $dbReader["mime_type"]
                original_mime_type = $dbReader["original_mime_type"]
            }
            $downloads_table_objects.Add($tmp) | Out-Null
        }
    }
    $dbReader.Close()
}
### END SECTION: HISTORY PARSING

function Main {
    $targets = Get-ChildItem $base_evidence_dir | Where { $_.PSIsContainer }
    Write-Host "[+] Parsing Chrome User Data..."
    Write-Host "[+] Found $($targets.Count) Targets..."
    ForEach ($target in $targets){
        Write-Host "[+] Processing: $target"
        Find-Extension-Manifest $target
        Parse-History $target
    }
}

Main