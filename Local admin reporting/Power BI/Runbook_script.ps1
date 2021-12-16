#*******************************************************
# Part to fill
$ResourceGroup = ""
$StorageAccount = ""
$container = ""
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

# Get info about proactive remediation
$Main_Path = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"

$headers = @{'Authorization'="Bearer " + $accessToken}

$Get_script_info = Invoke-WebRequest -Uri $Main_Path -Method GET -Headers $Headers -UseBasicParsing 
$Main_JsonResponse = ($Get_script_info.Content | ConvertFrom-Json).value
$result = $Main_JsonResponse | Where{$_.DisplayName -eq "$Script_name"}
$Get_Script_ID = $result.id

$Get_Script_Details_URL = "$Main_Path/$Get_Script_ID/deviceRunStates/" + '?$expand=*'

$Details_GraphRequest = Invoke-WebRequest -Uri $Get_Script_Details_URL -Method GET -Headers $Headers -UseBasicParsing 
$Details_JsonResponse = ($Details_GraphRequest.Content | ConvertFrom-Json)
$Script_Details = $Details_JsonResponse.value
If($Details_JsonResponse.'@odata.nextLink')
{
	do {
		$URL = $Details_JsonResponse.'@odata.nextLink'
        $Details_GraphRequest = Invoke-WebRequest -Uri $URL -Method GET -Headers $Headers -UseBasicParsing 
		$Details_JsonResponse = ($Details_GraphRequest.Content | ConvertFrom-Json)
		$Script_Details += $Details_JsonResponse.value
	} until ($null -eq $Details_JsonResponse.'@odata.nextLink')
}

$Remediation_details = @()
ForEach($Detail in $Script_Details)
	{
		$Remediation_Values = New-Object PSObject
		$userPrincipalName = $Detail.managedDevice.userPrincipalName      
		$deviceName = $Detail.managedDevice.deviceName
		$osVersion = $Detail.managedDevice.osVersion		
		$Script_lastStateUpdateDateTime = $Detail.lastStateUpdateDateTime                                        
		$Script_lastSyncDateTime = $Detail.lastSyncDateTime                                 
		$Script_DetectionScriptOutput = $Detail.preRemediationDetectionScriptOutput  

		If($Script_DetectionScriptOutput -ne $null)
			{
				ForEach($Result in $Script_DetectionScriptOutput)
					{
						$Split_Result = $Result.Split(";").Trim()
						$Model = $Split_Result[0]
						$Admin_Status = $Split_Result[1]
						$Admin_Count = $Split_Result[2]
						$Admin_Accounts = ($Split_Result[3]).Replace("^","`n")
												
						$Remediation_Values = New-Object PSObject
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device name" $deviceName -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "User name" $userPrincipalName -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "OS version" $osVersion -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device model" $Model -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Local admin status" $Admin_Status -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Local admin count" $Admin_Count -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Local admin accounts" $Admin_Accounts -passthru -force
						$Remediation_details += $Remediation_Values
					}
			}
	} 

$CSV_Name = "$Script_name.csv"
$CSV_Full_Path = "$env:Temp\$CSV_Name"

$NewFile = New-Item -ItemType File -Name $CSV_Name
$Remediation_details | select * | export-csv $CSV_Full_Path -notype -Delimiter ","  

$StorageAccount = Get-AzStorageAccount -Name $StorageAccount -ResourceGroupName $ResourceGroup
Set-AzStorageBlobContent -File $CSV_Full_Path -Container $Container -Blob $CSV_Name -Context $StorageAccount.Context -Force -ErrorAction Stop