# SHAREPOINT APPLICATION PART
$ClientID = "" # SHAREPOINT APP CLIENT ID
$Secret = '' # SHAREPOINT APP CLIENT SECRET
$Site_URL = "" # SHAREPOINT SITE
$Folder_Location = "" # SHAREPOINT FOLDER WHERE TO SEND CSV

# AUTHENTICATE TO TENANT WITH THE MANAGED IDENTITY
$url = $env:IDENTITY_ENDPOINT  
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$headers.Add("Metadata", "True") 
$body = @{resource='https://graph.microsoft.com/' } 
$script:accessToken = (Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body ).access_token
Connect-AzAccount -Identity
$headers = @{'Authorization'="Bearer " + $accessToken}

# REPORT TO COLLECT
# More info here: https://learn.microsoft.com/en-us/mem/intune/fundamentals/reports-export-graph-available-reports
# AppInvRawData: Under Apps > Monitor > Discovered apps > Export

$body = @"
{ 
    "reportName": "AppInvRawData", 
    "select": ["DeviceName","DeviceId","ApplicationName","ApplicationVersion","Platform","UserName"],
    "format": "csv", 		
    "localizationType": "LocalizedValuesAsAdditionalColumn"
} 
"@



# GET REPORT CONTENT URL
$URL = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs"
$Export_Job = Invoke-WebRequest -Uri $URL -Method POST -Headers $Headers -UseBasicParsing -Body $Body -ContentType "application/json" 
$Apps_ID = ($Export_Job.Content | ConvertFrom-Json).id
$Status_Info = Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$Apps_ID')" -Method GET -Headers $Headers -UseBasicParsing 
$Get_Status = ($Status_Info.Content | ConvertFrom-Json)
Do{
    $Status_Info = Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$Apps_ID')" -Method GET -Headers $Headers -UseBasicParsing 
    $Get_Status = ($Status_Info.Content | ConvertFrom-Json).status 
} Until ($Get_Status -eq "completed")
$Status_Info = Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$Apps_ID')" -Method GET -Headers $Headers -UseBasicParsing 
$Resp = ($Status_Info.Content | ConvertFrom-Json)
$DiscoveredApps_URL = $Resp.url

New-Item -ItemType Directory -Name "DiscoveredApps"

$DiscoveredApps_ZIP = "DiscoveredApps.zip"
$DiscoveredApps_Windows_CSV = "DiscoveredApps_Windows.csv"

# GET THE REPORT AS ZIP
Invoke-WebRequest -Uri $DiscoveredApps_URL -OutFile $DiscoveredApps_ZIP
Expand-Archive $DiscoveredApps_ZIP -DestinationPath "./DiscoveredApps" 

# GET REPORT AS CSV
$DiscoveredApps_CSV = (gci .\DiscoveredApps | where {$_.Name -like "AppInvRawData*.csv"}).fullname
$Get_CSV_FirstLine = Get-Content $DiscoveredApps_CSV | Select -First 1
$Get_Delimiter = If($Get_CSV_FirstLine.Split(";").Length -gt 1){";"}Else{","};
$CSV_Content = import-csv $DiscoveredApps_CSV -Delimiter $Get_Delimiter | where {$_.Platform -eq "windows"}
New-Item -ItemType File -Name $DiscoveredApps_Windows_CSV
$CSV_Content | export-csv $DiscoveredApps_Windows_CSV -notypeinformation

# CONNECT TO SHAREPOINT
Connect-PnPOnline -Url $Site_URL -ClientId $ClientID -ClientSecret $Secret -WarningAction Ignore
# SEND CSV TO SHAREPOINT
Add-PnPFile -Path $DiscoveredApps_Windows_CSV -Folder $Folder_Location | out-null
Disconnect-pnponline

