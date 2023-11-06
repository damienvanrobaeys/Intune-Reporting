#$Custom_Logs = "Export_DiscoveredApps"
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$TimeStampField = ""
$Custom_log = "Intune_DiscoveredApps"

$ClientID = ""
$Secret = ''    
$Site_URL = ""
$Folder_Location = ""

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

Connect-PnPOnline -Url $Site_URL -ClientId $ClientID -ClientSecret $Secret -WarningAction Ignore

$Get_WindowsApps_CSV = Get-PnPFolderItem -FolderSiteRelativeUrl "Documents partages/Windows/Apps_Report" | where {$_.Name -like "DiscoveredApps_Windows.csv*"}

$CSV_URL = $Get_WindowsApps_CSV.ServerRelativeUrl
Get-PnPFile -Url $CSV_URL -Path $env:temp -FileName "DiscoveredApps_Windows.csv" -AsFile -Force
$File_Path = "$env:temp\DiscoveredApps_Windows.csv"

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
