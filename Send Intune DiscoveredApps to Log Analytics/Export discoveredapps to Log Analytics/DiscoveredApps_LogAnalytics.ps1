# Log Analytics info
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$TimeStampField = ""
$Custom_log = "Intune_DiscoveredApps"

# SharePoint info
$Tenant = ""  # tenant name
$ClientID = "" # azure app client id 
$Secret = '' # azure app secret
$SharePoint_SiteID = ""  # sharepoint site id	
$SharePoint_Path = "https://grtgaz.sharepoint.com/sites/DWP-Support/Documents%20partages"  # sharepoint main path
# Somethinhg like "https://systanddeploy.sharepoint.com/sites/Support/Documents%20partages"
$SharePoint_ExportFolder = "Windows/Apps_Report"  # folder where to upload file
# Something like "Windows/Apps_Report"
$CSV_DiscoveredApps_Windows = "DiscoveredApps_Windows.csv"
$FileName = $CSV_DiscoveredApps_Windows.Split("\")[-1]  

<#
Now to get the ID of a SharePoint site proceed as below:
1. Open your browser
2. Type the following URL: 
https://yoursharepoint.sharepoint.com/sites/yoursite/_api/site/id

In my case it's:
https://systanddeploy.sharepoint.com/sites/Support/_api/site/id
#>

# Log analytics functions
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Create the function to create and post the request
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    return $response.StatusCode
}

$Body = @{  
	client_id = $ClientID
	client_secret = $Secret
	scope = "https://graph.microsoft.com/.default"   
	grant_type = 'client_credentials'  
}  
	
$Graph_Url = "https://login.microsoftonline.com/$($Tenant).onmicrosoft.com/oauth2/v2.0/token"  
$AuthorizationRequest = Invoke-RestMethod -Uri $Graph_Url -Method "Post" -Body $Body  

$Access_token = $AuthorizationRequest.Access_token  
$Header = @{  
	Authorization = $AuthorizationRequest.access_token  
	"Content-Type"= "application/json"  
	'Content-Range' = "bytes 0-$($fileLength-1)/$fileLength"	
}  

$SharePoint_Graph_URL = "https://graph.microsoft.com/v1.0/sites/$SharePoint_SiteID/drives"  
$BodyJSON = $Body | ConvertTo-Json -Compress  

$Result = Invoke-RestMethod -Uri $SharePoint_Graph_URL -Method 'GET' -Headers $Header -ContentType "application/json"   
$DriveID = $Result.value| Where-Object {$_.webURL -eq $SharePoint_Path } | Select-Object id -ExpandProperty id  
$FileName = $CSV_DiscoveredApps_Windows.Split("\")[-1]  
$fileurl = "https://graph.microsoft.com/v1.0/sites/$SharePoint_SiteID/drives/$DriveID/root:/$SharePoint_ExportFolder/$($fileName):/content"
$File_Path = "$env:temp\DiscoveredApps_Windows.csv"

Try
	{
		Invoke-RestMethod -Headers $Header -Uri $fileurl -OutFile $File_Path		
	}
Catch
	{
		EXIT
	}

$InputFilename = [System.IO.File]::ReadAllLines($File_Path)
$OutputFilenamePattern = ".\Export_"
$LineLimit = 1000
$line = 0
$i = 0
$file = 0
$start = 0
While ($line -le $InputFilename.Length){
	If($i -eq $LineLimit -Or $line -eq $InputFilename.Length) 
		{
			$file++
			$CSV_File = "$OutputFilenamePattern$file.csv"
			$InputFilename[$start..($line-1)] | Out-File $CSV_File -Force
			("DeviceName,DeviceId,ApplicationName,ApplicationVersion,Platform,UserName", (Get-Content -Path $CSV_File)) | Set-Content $CSV_File 
			$start = $line;
			$i = 0

			$Get_CSV_FirstLine = Get-Content $CSV_File | Select -First 1
			$Get_Delimiter = If($Get_CSV_FirstLine.Split(";").Length -gt 1){";"}Else{","};			
			$LA_CSV = import-csv $CSV_File -Delimiter $Get_Delimiter	
                 
			$InfoToImport_Json = $LA_CSV | ConvertTo-Json
			$params = @{
				CustomerId = $customerId
				SharedKey  = $sharedKey
				Body       = ([System.Text.Encoding]::UTF8.GetBytes($InfoToImport_Json))
				LogType    = $Custom_log 
			}
			$LogResponse = Post-LogAnalyticsData @params
                      
			$CSV_File
            [System.GC]::GetTotalMemory($true) | out-null
		}
	$i++;
	$line++
}
