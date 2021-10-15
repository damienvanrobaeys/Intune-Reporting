#*******************************************************
# Part to fill
$ResourceGroup = ""
$StorageAccount = ""
$container = "powerbi-csv"
$TempFolder = "$env:Temp"
$Script_name = "Check local admin" # Name of the proactive remediation script
#
#*******************************************************

$url = $env:IDENTITY_ENDPOINT  
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$headers.Add("Metadata", "True") 
$body = @{resource='https://graph.microsoft.com/' } 
$script:accessToken = (Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body ).access_token

Connect-AzAccount -Identity

$Main_Path = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"

$headers = @{'Authorization'="Bearer " + $accessToken}
$Get_script_info = Invoke-WebRequest -Uri $Main_Path -Method GET -Headers $Headers -UseBasicParsing 
$JsonResponse = ($Get_script_info.Content | ConvertFrom-Json).value
$result = $JsonResponse | Where{$_.DisplayName -eq "$Script_name"}
$Get_Script_ID = $result.id

$Output_Details = "$Main_Path/$Get_Script_ID/deviceRunStates/" + '?$expand=*'
$Get_script_details = Invoke-WebRequest -Uri $Output_Details -Method GET -Headers $Headers -UseBasicParsing 
$Details_JsonResponse = ($Get_script_details.Content | ConvertFrom-Json).value

$Remediation_details = @()
ForEach($Detail in $Details_JsonResponse)
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
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Last sync" $Script_lastSyncDateTime -passthru -force
		$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Local admin" $Script_DetectionScriptOutput -passthru -force
		$Remediation_details += $Remediation_Values
	} 

$CSV_Name = "$Script_name.csv"
$CSV_Full_Path = "$env:Temp\$CSV_Name"

$NewFile = New-Item -ItemType File -Name $CSV_Name
$Remediation_details | select * | export-csv $CSV_Full_Path -notype -Delimiter ","  

$StorageAccount = Get-AzStorageAccount -Name $StorageAccount -ResourceGroupName $ResourceGroup
Set-AzStorageBlobContent -File $CSV_Full_Path -Container $Container -Blob $CSV_Name -Context $StorageAccount.Context -Force -ErrorAction Stop