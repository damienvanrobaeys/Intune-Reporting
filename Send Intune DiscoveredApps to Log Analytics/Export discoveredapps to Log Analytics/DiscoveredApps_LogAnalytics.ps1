$Custom_Logs = "Export_DiscoveredApps"
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$TimeStampField = ""

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

# SHAREPOINT APPLICATION PART
$ClientID = "" # SHAREPOINT APP CLIENT ID
$Secret = '' # SHAREPOINT APP CLIENT SECRET
$Site_URL = "" # SHAREPOINT SITE
$Folder_Location = "" # SHAREPOINT FOLDER WHERE TO SEND CSV

# CONNECT TO SHAREPOINT
Connect-PnPOnline -Url $Site_URL -ClientId $ClientID -ClientSecret $Secret -WarningAction Ignore

# GET DISCOVEREDAPPS CSV FROM SHAREPOINT
$Get_WindowsApps_CSV = Get-PnPFolderItem -FolderSiteRelativeUrl "Documents partages/Windows/Apps_Report" | where {$_.Name -like "*_Windows.csv*"}
$CSV_URL = $Get_WindowsApps_CSV.ServerRelativeUrl
Get-PnPFile -Url $CSV_URL -Path $env:temp -FileName "DiscoveredApps_Windows.csv" -AsFile -Force
$File_Path = "$env:temp\DiscoveredApps_Windows.csv"
$InputFilename = Get-Content $File_Path

# SPLIT FILE IN MULTIPLE CSV
# Special thank for this: https://www.spjeff.com/2017/06/02/powershell-split-csv-in-1000-line-batches/
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

			# CONVERT EACH CSV TO JSON
			$InfoToImport_Json = $LA_CSV | ConvertTo-Json
			$params = @{
				CustomerId = $customerId
				SharedKey  = $sharedKey
				Body       = ([System.Text.Encoding]::UTF8.GetBytes($InfoToImport_Json))
				LogType    = "DiscoveredApps" 
			}

			# SEND CSV CONTENT TO LOG ANALYTICS			
			$LogResponse = Post-LogAnalyticsData @params

			$CSV_File

			write-host "Memory used after full collection: $([System.GC]::GetTotalMemory($true))"
		}
	$i++;
	$line++
}