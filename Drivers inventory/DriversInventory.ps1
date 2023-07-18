# Log analytics part
$LogType = "DriversInventory"
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
""
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

$win32_computersystem = gwmi win32_computersystem
$Manufacturer = $win32_computersystem.Manufacturer
$Model = $win32_computersystem.Model
If($Manufacturer -like "*lenovo*")
	{
		$Model_FriendlyName = $win32_computersystem.SystemFamily
		$Get_Current_Model =  $Model.Substring(0,4)
	}Else
	{
		$Model_FriendlyName = $Model
		$Get_Current_Model = $Model_FriendlyName
	}	

$PNPSigned_Drivers = gwmi Win32_PnPSignedDriver | where {($_.manufacturer -ne "microsoft") -and ($_.driverprovidername -ne "microsoft") -and`
($_.DeviceName -ne $null)} | select-object @{Label="DeviceName";Expression={$_.PSComputerName}},`
@{Label="ModelFriendlyName";Expression={$Model_FriendlyName}},`
@{Label="DeviceManufacturer";Expression={$Manufacturer}},`
@{Label="Model";Expression={$Model}},`
@{Label="DriverName";Expression={$_.DeviceName}},DriverVersion,`
@{Label="DriverDate";Expression={$_.ConvertToDateTime($_.DriverDate)}},`
DeviceClass, DeviceID, manufacturer 

$Drivers_Json = $PNPSigned_Drivers | ConvertTo-Json

$params = @{
	CustomerId = $customerId
	SharedKey  = $sharedKey
	Body       = ([System.Text.Encoding]::UTF8.GetBytes($Drivers_Json))
	LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params	