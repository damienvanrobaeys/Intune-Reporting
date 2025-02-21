# Log analytics part
$LogType_Inventory = "DriversInventory"
$LogType_Translation = "DriversInventory_Translate"
$LogType_Optional_Updates = "OptionalUpdates"
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

# GET MODEL INFO
$win32_computersystem = gwmi win32_computersystem
$Manufacturer = $win32_computersystem.Manufacturer
$Model = $win32_computersystem.Model
If($Manufacturer -like "*lenovo*")
	{
		$Model_FriendlyName = $win32_computersystem.SystemFamily
	}Else
	{
		$Model_FriendlyName = $Model
	}	

# COLLECT DRIVERS IN ARRAY
$PNPSigned_Drivers = gwmi win32_PnpSignedDriver | where {($_.manufacturer -ne "microsoft") -and ($_.driverprovidername -ne "microsoft") -and`
($_.DeviceName -ne $null)} | select-object @{Label="DeviceName";Expression={$env:computername}},`
@{Label="ModelFriendlyName";Expression={$Model_FriendlyName}},`
@{Label="DeviceManufacturer";Expression={$Manufacturer}},`
@{Label="Model";Expression={$Model}},`
@{Label="DriverName";Expression={$_.DeviceName}},DriverVersion,`
@{Label="DriverDate";Expression={$_.ConvertToDateTime($_.DriverDate)}},`
DeviceClass, DeviceID, manufacturer,InfName,Location

# CONVERT ARRAY TO JSON
$Drivers_Json = $PNPSigned_Drivers | ConvertTo-Json

# Translating Windows Update Driver Names to Friendly Driver Names
# Thanks to Trevor Jones for this 
# https://smsagent.blog/2023/07/07/translating-windows-update-driver-names-to-friendly-driver-names/
class Driver {
    [string]$WUName 
    [datetime]$InstallDate
    [string]$DeviceName 
    [string]$FriendlyName
    [datetime]$DriverDate 
    [string]$DriverVersion 
    [string]$Manufacturer
}
$DriverList = [System.Collections.Generic.List[Driver]]::new()
$InstalledDrivers = Get-Package -ProviderName msu | where {$_.Metadata.Item("SupportUrl") -match "target=hub"}
foreach($InstalledDriver in $InstalledDrivers)
{
    $Driver = [Driver]::new()
    $Driver.WUName = $InstalledDriver.Name
    $Driver.InstallDate = [DateTime]::Parse($InstalledDriver.Metadata.Item("Date"))
    $DeviceDriver = Get-CimInstance -ClassName Win32_PnPSignedDriver -Filter "DriverVersion = '$($InstalledDriver.Name.Split()[-1])'" | 
        Select -First 1 | 
        Select DeviceName,FriendlyName,DriverDate,DriverVersion,Manufacturer
    If ($DeviceDriver)
    {
        try { $DriverDate = [DateTime]::Parse($DeviceDriver.DriverDate) }catch { $DriverDate = $DeviceDriver.DriverDate }
        $Driver.DeviceName = $DeviceDriver.DeviceName
        $Driver.DeviceName = $DeviceDriver.DeviceName		
        $Driver.FriendlyName = $DeviceDriver.FriendlyName
        $Driver.DriverDate = $DriverDate
        $Driver.DriverVersion = $DeviceDriver.DriverVersion
        $Driver.Manufacturer = $DeviceDriver.Manufacturer
        $DriverList.Add($Driver)
    }  
}
$Drivers_Translate = $DriverList | select-object @{Label="DeviceName";Expression={$env:computername}},`
@{Label="ModelFriendlyName";Expression={$Model_FriendlyName}},`
@{Label="DeviceManufacturer";Expression={$Manufacturer}},`
@{Label="Model";Expression={$Model}},`
@{Label="WUName";Expression={$_.WUName}},`
@{Label="DriverName";Expression={$_.DeviceName}},`
@{Label="DriverFriendlyName";Expression={$_.FriendlyName}},`
@{Label="DriverManufacturer";Expression={$_.Manufacturer}},DriverVersion,DriverDate

# CONVERT ARRAY TO JSON
$DriverList_Translation_Json = $Drivers_Translate | ConvertTo-Json

# GETTING INFO ABOUT OPTIONAL UPDATES
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()
$searchResult = $updateSearcher.Search("IsInstalled=0 AND Type='Driver'")
$OptionalWUList = @()
If($searchResult.Updates.Count -gt 0) 
	{
		For($i = 0; $i -lt $searchResult.Updates.Count; $i++) 
			{
				$update = $searchResult.Updates.Item($i)
				$OptionalWUList += [PSCustomObject]@{
					Title            = $update.Title
					Description      = $update.Description
					DriverClass      = $update.DriverClass
					DriverModel      = $update.DriverModel
					DriverChangeTime = $update.LastDeploymentChangeTime
				}
			}
	}

$Optional_Drivers = $OptionalWUList | select-object @{Label="DeviceName";Expression={$env:computername}},`
@{Label="ModelFriendlyName";Expression={$Model_FriendlyName}},`
@{Label="DeviceManufacturer";Expression={$Manufacturer}},`
@{Label="Model";Expression={$Model}},Title,Description,DriverClass,DriverModel,DriverChangeTime

# CONVERT ARRAY TO JSON
$Optional_Updates_Inventory_Json = $Optional_Drivers | ConvertTo-Json

# SEND JSON CONTENT TO LOG ANALYTICS
$params = @{
	CustomerId = $customerId
	SharedKey  = $sharedKey
	Body       = ([System.Text.Encoding]::UTF8.GetBytes($Drivers_Json))
	LogType    = $LogType_Inventory 
}
$LogResponse = Post-LogAnalyticsData @params	

$params = @{
	CustomerId = $customerId
	SharedKey  = $sharedKey
	Body       = ([System.Text.Encoding]::UTF8.GetBytes($DriverList_Translation_Json))
	LogType    = $LogType_Translation 
}
$LogResponse = Post-LogAnalyticsData @params	

$params = @{
	CustomerId = $customerId
	SharedKey  = $sharedKey
	Body       = ([System.Text.Encoding]::UTF8.GetBytes($Optional_Updates_Inventory_Json))
	LogType    = $LogType_Optional_Updates 
}
$LogResponse = Post-LogAnalyticsData @params	