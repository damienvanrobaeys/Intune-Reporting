#=============================================================
# Config
#=============================================================
# Azure application
$tenant = ""
$authority = "https://login.windows.net/$tenant"
$clientId = ""
$clientSecret = ''
$Script_name = "Export drivers status"

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
		
		$Script_lastStateUpdateDateTime = $Detail.lastStateUpdateDateTime
		$Script_Detection_Output   = $Detail.preRemediationDetectionScriptOutput  
		$deviceName = $Detail.managedDevice.deviceName
		$detectionState = $Detail.detectionState
		$userPrincipalName = ($Detail.managedDevice.userPrincipalName).split("@")[0]

		$Split_Detection_Output = $Script_Detection_Output.Split("-").Trim()
		If($Script_Detection_Output -ne $null)
			{
				ForEach($Driver in $Split_Detection_Output)
					{
						$Driver = $Driver.Split(";").Trim()
						$Error_Type = $Driver[1]
						$Driver_Name = $Driver[2]
						$Device_ID = $Driver[3]
						
						$Remediation_Values = New-Object PSObject
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Status" $detectionState -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device name" $deviceName -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "User name" $userPrincipalName -passthru -force 
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Error" $Error_Type -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Driver name" $Driver_Name -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device ID" $Device_ID -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Last check" $Script_lastStateUpdateDateTime -passthru -force
						$Remediation_details += $Remediation_Values
					}
				break			
			}
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