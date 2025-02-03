# Information about SharePoint app
$Tenant = ""  # tenant name
$ClientID = "" # azure app client id 
$Secret = '' # azure app secret
$SharePoint_SiteID = ""  # sharepoint site id	
$SharePoint_Path = ""  # sharepoint main path 
# Somethinhg like "https://systanddeploy.sharepoint.com/sites/Support/Documents%20partages"
$SharePoint_ExportFolder = ""  # folder where to upload file 
# Something like "Windows/Apps_Report"
$CSV_DiscoveredApps_All = "DiscoveredApps_All.csv"
$CSV_DiscoveredApps_Windows = "DiscoveredApps_Windows.csv"

<#
Now to get the ID of a SharePoint site proceed as below:
1. Open your browser
2. Type the following URL: 
https://yoursharepoint.sharepoint.com/sites/yoursite/_api/site/id

In my case it's:
https://systanddeploy.sharepoint.com/sites/Support/_api/site/id
#>

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


$Body = @{  
	client_id = $ClientID
	client_secret = $Secret
	scope = "https://graph.microsoft.com/.default"   
	grant_type = 'client_credentials'  
}  
	
$Graph_Url = "https://login.microsoftonline.com/$($Tenant).onmicrosoft.com/oauth2/v2.0/token"  
Try
	{
		$AuthorizationRequest = Invoke-RestMethod -Uri $Graph_Url -Method "Post" -Body $Body  
	}
Catch
	{
		EXIT
	}
	
$Access_token = $AuthorizationRequest.Access_token  
$Header = @{  
	Authorization = $AuthorizationRequest.access_token  
	"Content-Type"= "application/json"  
	'Content-Range' = "bytes 0-$($fileLength-1)/$fileLength"	
}  

$SharePoint_Graph_URL = "https://graph.microsoft.com/v1.0/sites/$SharePoint_SiteID/drives"  
$BodyJSON = $Body | ConvertTo-Json -Compress  

Try
	{
		$Result = Invoke-RestMethod -Uri $SharePoint_Graph_URL -Method 'GET' -Headers $Header -ContentType "application/json"   
	}
Catch
	{
		EXIT
	}

$DriveID = $Result.value| Where-Object {$_.webURL -eq $SharePoint_Path } | Select-Object id -ExpandProperty id  

# Send CSV for all devices
$FileName = $CSV_DiscoveredApps_All.Split("\")[-1]  
$createUploadSessionUri = "https://graph.microsoft.com/v1.0/sites/$SharePoint_SiteID/drives/$DriveID/root:/$SharePoint_ExportFolder/$($fileName):/createUploadSession"

Try
	{
		$uploadSession = Invoke-RestMethod -Uri $createUploadSessionUri -Method 'POST' -Headers $Header -ContentType "application/json" 
	}
Catch
	{
		EXIT
	}

$fileInBytes = [System.IO.File]::ReadAllBytes($CSV_DiscoveredApps_All)
$fileLength = $fileInBytes.Length

$headers = @{
'Content-Range' = "bytes 0-$($fileLength-1)/$fileLength"
}
$response = Invoke-RestMethod -Method 'Put' -Uri $uploadSession.uploadUrl -Body $fileInBytes -Headers $headers

# Send CSV for Windows
$FileName = $CSV_DiscoveredApps_Windows.Split("\")[-1]  
$createUploadSessionUri = "https://graph.microsoft.com/v1.0/sites/$SharePoint_SiteID/drives/$DriveID/root:/$SharePoint_ExportFolder/$($fileName):/createUploadSession"

Try
	{
		$uploadSession = Invoke-RestMethod -Uri $createUploadSessionUri -Method 'POST' -Headers $Header -ContentType "application/json" 
	}
Catch
	{
		EXIT
	}
	
$fileInBytes = [System.IO.File]::ReadAllBytes($CSV_DiscoveredApps_Windows)
$fileLength = $fileInBytes.Length
$headers = @{
'Content-Range' = "bytes 0-$($fileLength-1)/$fileLength"
}

$response = Invoke-RestMethod -Method 'Put' -Uri $uploadSession.uploadUrl -Body $fileInBytes -Headers $headers