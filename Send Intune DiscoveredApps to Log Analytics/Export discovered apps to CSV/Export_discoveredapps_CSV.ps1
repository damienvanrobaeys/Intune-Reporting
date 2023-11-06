<#
See below posts for more info:
https://www.systanddeploy.com/2022/02/how-to-use-teamssharepoint-as-logs.html
https://www.systanddeploy.com/2021/02/upload-files-to-sharepointteams-using.html
#>

$ClientID = ""
$Secret = ''    
$Site_URL = ""
$Folder_Location = ""

$url = $env:IDENTITY_ENDPOINT  
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$headers.Add("Metadata", "True") 
$body = @{resource='https://graph.microsoft.com/' } 
$script:accessToken = (Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body ).access_token

Connect-AzAccount -Identity
$headers = @{'Authorization'="Bearer " + $accessToken}


$body = @"
{ 
    "reportName": "AppInvRawData", 
    "select": ["DeviceName","DeviceId","ApplicationName","ApplicationVersion","Platform","UserName"],
    "format": "csv", 		
    "localizationType": "LocalizedValuesAsAdditionalColumn"
} 
"@

$URL = "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs"
$Export_Job = Invoke-WebRequest -Uri $URL -Method POST -Headers $Headers -UseBasicParsing -Body $Body -ContentType "application/json" #| out-null
$Apps_ID = ($Export_Job.Content | ConvertFrom-Json).id
$Status_Info = Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$Apps_ID')" -Method GET -Headers $Headers -UseBasicParsing 

Do{
    $Get_Status = ((Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$Apps_ID')" -Method GET -Headers $Headers -UseBasicParsing).Content | ConvertFrom-Json).status
	If($Get_Status -eq "inProgress")
		{
			write-host "Still in progress"
			start-sleep 5
		}     

} Until ($Get_Status -eq "completed")

$Status_Info = Invoke-WebRequest -Uri "https://graph.microsoft.com/beta/deviceManagement/reports/exportJobs('$Apps_ID')" -Method GET -Headers $Headers -UseBasicParsing 
$Resp = ($Status_Info.Content | ConvertFrom-Json)
$DiscoveredApps_URL = $Resp.url

Invoke-WebRequest -Uri $DiscoveredApps_URL -OutFile "DiscoveredApps.zip"
Expand-Archive "DiscoveredApps.zip" -DestinationPath "./" 

$DiscoveredApps_CSV = (gci .\ | where {$_.Name -like "AppInvRawData*.csv"}).fullname
Rename-Item -Path $DiscoveredApps_CSV -NewName "DiscoveredApps_All.csv"

$Get_CSV_FirstLine = Get-Content .\DiscoveredApps_All.csv | Select -First 1

$Get_Delimiter = If($Get_CSV_FirstLine.Split(";").Length -gt 1){";"}Else{","};
import-csv .\DiscoveredApps_All.csv -Delimiter $Get_Delimiter | where {$_.Platform -eq "windows"} | export-csv .\DiscoveredApps_Windows.csv -NoTypeInformation

Connect-PnPOnline -Url $Site_URL -ClientId $ClientID -ClientSecret $Secret -WarningAction Ignore
Add-PnPFile -Path .\DiscoveredApps_All.csv -Folder $Folder_Location | out-null
Add-PnPFile -Path .\DiscoveredApps_Windows.csv -Folder $Folder_Location | out-null
Disconnect-pnponline


