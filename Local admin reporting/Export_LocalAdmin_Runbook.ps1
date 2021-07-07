#=============================================================
# Config
#=============================================================
# Azure application
$tenant = ""
$authority = "https://login.windows.net/$tenant"
$clientId = ""
$clientSecret = ''
$Script_name = "Check local admin"

# Sharepoint application in case of export on Sharepoint
$app_id = ""
$App_Secret = ''
$Upload_Folder = ""
$Site_URL = ""
#=============================================================
#=============================================================


Update-MSGraphEnvironment -AppId $clientId -Quiet
Update-MSGraphEnvironment -AuthUrl $authority -Quiet
Connect-MSGraph -ClientSecret $ClientSecret -Quiet

$Main_Path = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"
$Get_script_info = (Invoke-MSGraphRequest -Url $Main_Path -HttpMethod Get).value | Where{$_.DisplayName -like "*$Script_name*"}

$Get_Script_ID = $Get_script_info.id
$Get_Script_Name = $Get_script_info.displayName

$Main_Details_Path = "$Main_Path/$Get_Script_ID/deviceRunStates/" + '?$expand=*'
$Get_script_details = (Invoke-MSGraphRequest -Url $Main_Details_Path -HttpMethod Get).value      

$Remediation_details = @()
ForEach($Detail in $Get_script_details)
	{
		$Remediation_Values = New-Object PSObject
		$userPrincipalName = $Detail.managedDevice.userPrincipalName      
		$deviceName = $Detail.managedDevice.deviceName
		$osVersion = $Detail.managedDevice.osVersion		
		$Script_lastStateUpdateDateTime = $Detail.lastStateUpdateDateTime                                        
		$Script_lastSyncDateTime = $Detail.lastSyncDateTime                                 
		$Script_DetectionScriptOutput   = $Detail.preRemediationDetectionScriptOutput  

		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device name" $deviceName -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "User name" $userPrincipalName -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "OS version" $osVersion -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Last update" $Script_lastStateUpdateDateTime -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Last sync" $Script_lastSyncDateTime -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Local admin" $Script_DetectionScriptOutput -passthru -force
		$Remediation_details += $Remediation_Values
	} 
	
$Remediation_Export_File = "$Get_Script_Name.csv"
$NewFile = New-Item -ItemType File -Name $Remediation_Export_File
$Remediation_details | select * | export-csv $Remediation_Export_File -notype -Delimiter ","

# Connect to the tenant
$connection = Get-AutomationConnection -Name AzureRunAsConnection
Login-AzureRmAccount `
-ServicePrincipal `
-Tenant $connection.TenantID `
-ApplicationId $connection.ApplicationID `
-CertificateThumbprint $connection.CertificateThumbprint

# Upload file on the blob storage
$acctKey = (Get-AzureRmStorageAccountKey -Name biosmanagement -ResourceGroupName BIOS).Key1
$storageContext = New-AzureStorageContext -StorageAccountName "biosmanagement" -StorageAccountKey $acctKey
Set-AzureStorageBlobContent -File $Remediation_Export_File -Container "bios-container" -BlobType "Block" -Context $storageContext -Force -Verbose	

# In case of export on Sharepoint
# connect-pnponline -url $Site_URL -clientid $app_id -ClientSecret $App_Secret
# Add-PnPFile -Path $Remediation_Export_File -Folder $Upload_Folder | out-null