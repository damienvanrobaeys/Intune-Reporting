#*******************************************************
# Part to fill
$StorageAccount = ""
$ResourceGroup = ""
$container = ""
$TempFolder = "$env:Temp"
$Script_name = "Compare BIOS" # Name of the proactive remediation script
#
#*******************************************************

$url = $env:IDENTITY_ENDPOINT  
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$headers.Add("Metadata", "True") 
$body = @{resource='https://graph.microsoft.com/' } 
$script:accessToken = (Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body ).access_token

Connect-AzAccount -Identity

$URL = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"

$headers = @{'Authorization'="Bearer " + $accessToken}
$Get_script_info = Invoke-WebRequest -Uri $URL -Method GET -Headers $Headers -UseBasicParsing 
$JsonResponse = ($Get_script_info.Content | ConvertFrom-Json).value
$result = $JsonResponse | Where{$_.DisplayName -eq "$Script_name"}

$Get_Script_ID = $result.id

$Output_Details = "$Main_Path/$Get_Script_ID/deviceRunStates/" + '?$expand=*'
$Get_script_details = Invoke-WebRequest -Uri $Output_Details -Method GET -Headers $Headers -UseBasicParsing 
$Details_JsonResponse = ($Get_script_details.Content | ConvertFrom-Json).value
	
$Remediation_details = @()
ForEach($Detail in $Get_script_details | where {(($_.detectionState -eq "success") -and ($_.managedDevice.userPrincipalName -ne $null))})
	{
		$Script_lastStateUpdateDateTime = $Detail.lastStateUpdateDateTime
		$Script_Detection_Output   = $Detail.preRemediationDetectionScriptOutput  
		$deviceName = $Detail.managedDevice.deviceName
		$detectionState = $Detail.detectionState
		$userPrincipalName = ($Detail.managedDevice.userPrincipalName).split("@")[0]
		$Split_Detection_Output = $Script_Detection_Output.Split("-").Trim()
		If($Script_Detection_Output -ne $null)
			{
				ForEach($Result in $Split_Detection_Output)
					{
						$BIOS_Result = $Result.Split(";").Trim()
						$BIOS_Status = $BIOS_Result[0]
						$DayDelay = $BIOS_Result[1]
						$Model = $BIOS_Result[2]
						$Current_Version = $BIOS_Result[3]
						$New_Version = $BIOS_Result[4]
						$New_Date = $BIOS_Result[5]						
						$Current_Date = $BIOS_Result[6]
												
						$Remediation_Values = New-Object PSObject
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device name" $deviceName -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "User name" $userPrincipalName -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "OS version" $detectionState -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Device model" $Model -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "BIOS status" $BIOS_Status -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Not updated since (in days)" $DayDelay -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Current BIOS version" $Current_Version -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "New BIOS version" $New_Version -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "Current BIOS date" $Current_Date -passthru -force
						$Remediation_Values = $Remediation_Values | Add-Member NoteProperty "New BIOS date" $New_Date -passthru -force
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