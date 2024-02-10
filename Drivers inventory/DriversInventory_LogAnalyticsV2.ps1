$DcrImmutableId = "" # id available in DCR > JSON view > immutableId
$DceURI = "" # available in DCE > Logs Ingestion value
$Table = "DriversInventory_CL" # custom log to create

$tenantId = "" #the tenant ID in which the Data Collection Endpoint resides
$appId = "" #the app ID created and granted permissions
$appSecret = "" #the secret created for the above app - never store your secrets in the source code

$win32_computersystem = get-ciminstance win32_computersystem
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

$PNPSigned_Drivers = get-ciminstance win32_PnpSignedDriver | where {($_.manufacturer -ne "microsoft") -and ($_.driverprovidername -ne "microsoft") -and`
($_.DeviceName -ne $null)} | select-object @{label="TimeGenerated";Expression={get-date -Format "dddd MM/dd/yyyy HH:mm K"}},`
@{Label="DeviceName";Expression={$env:computername}},`
@{Label="ModelFriendlyName";Expression={$Model_FriendlyName}},`
@{Label="DeviceManufacturer";Expression={$Manufacturer}},`
@{Label="Model";Expression={$Model}},`
@{Label="DriverName";Expression={$_.DeviceName}},DriverVersion,`
@{Label="DriverDate";Expression={$_.ConvertToDateTime($_.DriverDate)}},`
DeviceClass, DeviceID, manufacturer,InfName,Location

Add-Type -AssemblyName System.Web

$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

$body = $PNPSigned_Drivers | ConvertTo-Json #-AsArray;
$headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
$uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2023-01-01";
$uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers;