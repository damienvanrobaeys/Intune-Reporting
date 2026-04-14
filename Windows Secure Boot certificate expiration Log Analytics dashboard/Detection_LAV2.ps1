$DcrImmutableId = "" # id available in DCR > JSON view > immutableId
$DceURI = "" # available in DCE > Logs Ingestion value
$Table = "SecureBootCertificate_CL" # custom log to create

$tenantId = "" #the tenant ID in which the Data Collection Endpoint resides
$appId = "" #the app ID created and granted permissions
$appSecret = "" #the secret created for the above app - never store your secrets in the source code

$Win32_ComputerSystem = get-ciminstance win32_computersystem -ErrorAction SilentlyContinue
$Win32_BIOS = Get-ciminstance Win32_BIOS -ErrorAction SilentlyContinue
$Win32_OperatingSystem = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue

$Servicing_Reg_Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\Servicing"
$SecureBoot_Root_Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot"

$Current_Date = get-date

# 1. Get device name
$DeviceName = $env:COMPUTERNAME

# 2. Get the Serial Number
$Serial_Number = $Win32_BIOS.SerialNumber

# 3. Get Manufacturer
$Manufacturer = $Win32_ComputerSystem.Manufacturer

# 4. Get Model SystemFamily
# $Model_SystemFamily = $Win32_ComputerSystem.SystemFamily

# 5. Get device model (for Lenovo)
If($Manufacturer -eq "Lenovo"){
	$MTM_Model = ($Win32_ComputerSystem.Model).Substring(0,4)
	$Model = $Win32_ComputerSystem.Model
	$ModelFriendlyName = $Win32_ComputerSystem.SystemFamily
}Else{
	$ModelFriendlyName = $Win32_ComputerSystem.Model
	$Model = $ModelFriendlyName	
}

# 6. Get BIOS version
$BIOS_info = $Win32_BIOS| select *
$BIOS_Maj_Version = $BIOS_info.SystemBiosMajorVersion 
$BIOS_Min_Version = $BIOS_info.SystemBiosMinorVersion 
$Get_Current_BIOS_Version = "$BIOS_Maj_Version.$BIOS_Min_Version"
$SMBIOSBIOSVersion = $Win32_BIOS.SMBIOSBIOSVersion

# 7. Get BIOS release date
$BIOS_Release_Date = $BIOS_Info.ReleaseDate	
If($null -ne $BIOS_Release_Date){
    $ReleaseDate_Days_Old = ($Current_Date - $BIOS_Release_Date)
    $BIOS_ReleaseDate_Days_Old = $ReleaseDate_Days_Old.Days
}Else{
    $BIOS_ReleaseDate_Days_Old = $null
}

# 8. Get OS Version
Try{
	$OSVersion = $Win32_OperatingSystem.Version
}Catch{
    $OSVersion = [System.Environment]::OSVersion.Version.ToString()
}

Try {
	$OS_Build = (get-itemproperty -path registry::"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -erroraction 'silentlycontinue').DisplayVersion
}Catch {
	$OS_Build = $false	
}

# 9. Get OS install date
$OS_InstallDate = (($Win32_OperatingSystem).InstallDate)

# 10. Is Secure Boot Enabled ?
Try {
    $Is_SecureBoot_Enabled = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
}Catch {
	$Is_SecureBoot_Enabled = $false	
}

# 11. Get device uptime
Try {
	$Device_Uptime = $Win32_OperatingSystem.LastBootUpTime 
	$Diff_boot_time = $Current_Date - $Device_Uptime
	$Boot_Uptime_Days = $Diff_boot_time.Days		
}Catch {
	$Device_Uptime = $null	
}

# 12. Check certificate in ActiveDB
$Cert_ActiveDB = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI db).bytes) -match 'Windows UEFI CA 2023')

# 13. Check certificate in DefaultDB
Try{
    $Cert_DefaultDB = ([System.Text.Encoding]::ASCII.GetString((Get-SecureBootUEFI dbdefault).bytes) -match 'Windows UEFI CA 2023')
}Catch{
    $Cert_DefaultDB = "Check firmware"
}

If($Cert_DefaultDB -eq $True)
{
	$Cert_DefaultDB_Status = "OK"
}ElseIf($Cert_DefaultDB -eq $False)
{
	$Cert_DefaultDB_Status = "Needs update"
}ElseIf($Cert_DefaultDB -eq "Check firmware")
{
	$Cert_DefaultDB_Status = "Check firmware"
}

# 14. Check HighConfidenceOptOut registry value: should be 0
Try{
	$HighConfidenceOptOut_Value = (Get-ItemProperty -Path $SecureBoot_Root_Path -Name "HighConfidenceOptOut" -ErrorAction SilentlyContinue).HighConfidenceOptOut
}Catch{
    $HighConfidenceOptOut_Value = $null	
}

# 15. Check MicrosoftUpdateManagedOptIn registry value: should be 1
Try{
	$MicrosoftUpdateManagedOptIn_Value = (Get-ItemProperty -Path $SecureBoot_Root_Path -Name "MicrosoftUpdateManagedOptIn" -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn
}Catch{
    $MicrosoftUpdateManagedOptIn_Value = $null	
}

# 16. Check AvailableUpdates registry value
Try{
	$AvailableUpdates_Value = (Get-ItemProperty -Path $SecureBoot_Root_Path -Name "AvailableUpdates" -ErrorAction SilentlyContinue).AvailableUpdates
	$AvailableUpdates_Convert_Hex = "0x{0:X}" -f $AvailableUpdates_Value
}Catch{
    $AvailableUpdates_Value = $null	
}

# 17. Check UEFICA2023Status registry value
# Should be UEFICA2023Status = Updated and WindowsUEFICA2023Capable = 2
$UEFICA2023Status_Value = (Get-ItemProperty -Path $Servicing_Reg_Path -Name "UEFICA2023Status" -ErrorAction SilentlyContinue).UEFICA2023Status
$WindowsUEFICA2023Capable_Value = (Get-ItemProperty -Path $Servicing_Reg_Path -Name "WindowsUEFICA2023Capable" -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
switch($UEFICA2023Status_Value){
    "Updated"{
        If($WindowsUEFICA2023Capable_Value -eq 2){
            $UEFICA2023Status_Label = "Secure Boot CA 2023 update complete. No action needed."
        }
        Else{
            $UEFICA2023Status_Label = "Status is Updated but Capable=$WindowsUEFICA2023Capable_Value (expected 2)"
        }
    }
    "InProgress"{
        $UEFICA2023Status_Label = "The update is actively in progress. Waiting for a reboot or scheduled task execution"
    }

    "NotStarted"{
        $UEFICA2023Status_Label = "The deployment is planned, but the update has not yet run."
    }

    default {
        $UEFICA2023Status_Label = "Unknown status: $UEFICA2023Status_Value"
    }
}

# 18. Check UEFICA2023Error registry value
Try{
	$UEFICA2023Error_Value = (Get-ItemProperty -Path $Servicing_Reg_Path -Name "UEFICA2023Error" -ErrorAction SilentlyContinue).UEFICA2023Error
}Catch{
    $UEFICA2023Error_Value = $null	
}

# 19. Check if the Secure Boot  scheduled task is enabled
Try{
	$SecureBoot_Task_Info = Get-ScheduledTask -TaskName Secure-Boot-Update
	If($SecureBoot_Task_Info -eq $null)
	{
		$secureBoot_Task_Status = "Not found"
		$secureBoot_Task_Enabled = "Not found"
	}Else{
		$Task_Status = $SecureBoot_Task_Info.State
		
		If($Task_Status -eq "Disabled")
		{
			$secureBoot_Task_Status = "Disabled"
			$secureBoot_Task_Enabled = $false
		}ElseIf(($Task_Status -eq "Ready") -or ($Task_Status -eq "Running")){
			$secureBoot_Task_Status = "Enabled"
			$secureBoot_Task_Enabled = $false		
		}else{
			$secureBoot_Task_Status = "Unknown"		
		}	
	}			
}
Catch{
	$secureBoot_Task_Status = "Error"
	$secureBoot_Task_Enabled = $false			
}

# Adapted from the Seciure Boot remediations script provided by MS (https://aka.ms/getsecureboot)
# Event IDs:
#   1801 - Secure Boot certificates have been updated but are not yet applied to the device firmware.
#   1808 - This device has updated Secure Boot CA/keys, update completed successfully
#   1795 - Firmware returned error when attempting to update a Secure Boot variable
#   1796 - The Secure Boot update failed to update 
#   1800 - A reboot is required before installing the Secure Boot update
#   1802 - The Secure Boot update was blocked due to a known firmware issue on the device
#   1803 - A PK-signed Key Exchange Key (KEK) cannot be found for this device. Check with the device manufacturer for proper key provisioning.
try {
    # Query all relevant Secure Boot event IDs
    $allEventIds = @(1795, 1796, 1800, 1801, 1802, 1803, 1808)
    $events = @(Get-WinEvent -FilterHashtable @{LogName='System'; ID=$allEventIds} -MaxEvents 50 -ErrorAction Stop)

    if ($events.Count -eq 0) {
		$Secure_Events_Label = "No Secure Boot events found in System log" 
		
        $latestEventId = $null
        $bucketId = $null
        $confidence = $null
        $skipReasonKnownIssue = $null
        $event1801Count = 0
        $event1808Count = 0
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false

    } else {
        # 16. LatestEventId
        $latestEvent = $events | Sort-Object TimeCreated -Descending | Select-Object -First 1
        if ($null -eq $latestEvent) {
            $latestEventId = $null
        } else {
            $latestEventId = $latestEvent.Id
        }

        # 17. BucketID - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketId:\s*(.+)') {
                $bucketId = $matches[1].Trim()
            } else {
                $bucketId = $null
            }
        } else {
            $bucketId = $null
        }

        # 18. Confidence - Extracted from Event 1801/1808
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'BucketConfidenceLevel:\s*(.+)') {
                $confidence = $matches[1].Trim()
            } else {
                $confidence = $null
            }
        } else {
            $confidence = $null
        }

        # 18b. SkipReason - Extract KI_<number> from SkipReason in the same event as BucketId
        # This captures Known Issue IDs that appear alongside BucketId/Confidence (not just Event 1802)
        $skipReasonKnownIssue = $null
        if ($null -ne $latestEvent -and $null -ne $latestEvent.Message) {
            if ($latestEvent.Message -match 'SkipReason:\s*(KI_\d+)') {
                $skipReasonKnownIssue = $matches[1]
            }
        }

        # 19. Event1801Count
        $event1801Array = @($events | Where-Object {$_.Id -eq 1801})
        $event1801Count = $event1801Array.Count

        # 20. Event1808Count
        $event1808Array = @($events | Where-Object {$_.Id -eq 1808})
        $event1808Count = $event1808Array.Count
        
        # Initialize error event variables
        $event1795Count = 0
        $event1795ErrorCode = $null
        $event1796Count = 0
        $event1796ErrorCode = $null
        $event1800Count = 0
        $rebootPending = $false
        $event1802Count = 0
        $knownIssueId = $null
        $event1803Count = 0
        $missingKEK = $false
        
        # Only check for error events if update is NOT complete
        # Skip error analysis if: 1808 is latest event OR UEFICA2023Status is "Updated"
        $updateComplete = ($latestEventId -eq 1808) -or ($uefica2023Status -eq "Updated")
        
        if (-not $updateComplete) {
            
            # 21. Event1795 - Firmware Error (capture error code)
            $event1795Array = @($events | Where-Object {$_.Id -eq 1795})
            $event1795Count = $event1795Array.Count
            if ($event1795Count -gt 0) {
                $latestEvent1795 = $event1795Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1795.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1795ErrorCode = $matches[1]
                }
            }
            
            # 22. Event1796 - Error Code Logged (capture error code)
            $event1796Array = @($events | Where-Object {$_.Id -eq 1796})
            $event1796Count = $event1796Array.Count
            if ($event1796Count -gt 0) {
                $latestEvent1796 = $event1796Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1796.Message -match '(?:error|code|status)[:\s]*(?:0x)?([0-9A-Fa-f]{8}|[0-9A-Fa-f]+)') {
                    $event1796ErrorCode = $matches[1]
                }
            }
            
            # 23. Event1800 - Reboot Needed (NOT an error - update will proceed after reboot)
            $event1800Array = @($events | Where-Object {$_.Id -eq 1800})
            $event1800Count = $event1800Array.Count
            $rebootPending = $event1800Count -gt 0
            if ($rebootPending) {
            }
            
            # 24. Event1802 - Known Firmware Issue (capture KI_<number> from SkipReason)
            $event1802Array = @($events | Where-Object {$_.Id -eq 1802})
            $event1802Count = $event1802Array.Count
            if ($event1802Count -gt 0) {
                $latestEvent1802 = $event1802Array | Sort-Object TimeCreated -Descending | Select-Object -First 1
                if ($latestEvent1802.Message -match 'SkipReason:\s*(KI_\d+)') {
                    $knownIssueId = $matches[1]
                }
            }
            
            # 25. Event1803 - Missing KEK Update (OEM needs to supply PK signed KEK)
            $event1803Array = @($events | Where-Object {$_.Id -eq 1803})
            $event1803Count = $event1803Array.Count
            $missingKEK = $event1803Count -gt 0
            if ($missingKEK) {
            }
        } else {
        }
    }
} catch {
    $latestEventId = $null
    $bucketId = $null
    $confidence = $null
    $skipReasonKnownIssue = $null
    $event1801Count = 0
    $event1808Count = 0
    $event1795Count = 0
    $event1795ErrorCode = $null
    $event1796Count = 0
    $event1796ErrorCode = $null
    $event1800Count = 0
    $rebootPending = $false
    $event1802Count = 0
    $knownIssueId = $null
    $event1803Count = 0
    $missingKEK = $false
}

If($Manufacturer -ne "Microsoft")
{
	If($Is_SecureBoot_Enabled -eq $true -and $UEFICA2023Status_Value -eq "Updated" -and $Cert_ActiveDB -eq $True -and $Cert_DefaultDB -eq $True -and $WindowsUEFICA2023Capable_Value -eq 2) 
	{
		$Global_Status = "Without issue"
	}Else{
		$Global_Status = "With issue"	
	}
}Else{
	If($Is_SecureBoot_Enabled -eq $true -and $UEFICA2023Status_Value -eq "Updated" -and $Cert_ActiveDB -eq $True -and $WindowsUEFICA2023Capable_Value -eq 2) 
	{
		$Global_Status = "Without issue"
	}Else{
		$Global_Status = "With issue"	
	}	
}

If($Manufacturer -eq "Microsoft")
{
	If($Is_SecureBoot_Enabled -eq $true -and $UEFICA2023Status_Value -eq "Updated" -and $Cert_ActiveDB -eq $True -and $WindowsUEFICA2023Capable_Value -eq 2) 
	{
		$Global_Status = "Without issue"
	}Else{
		$Global_Status = "With issue"	
	}	
}Else{	
	If($Is_SecureBoot_Enabled -eq $true -and $UEFICA2023Status_Value -eq "Updated" -and $Cert_ActiveDB -eq $True -and $Cert_DefaultDB -eq $True -and $WindowsUEFICA2023Capable_Value -eq 2) 
	{
		$Global_Status = "Without issue"
	}Else{
		$Global_Status = "With issue"	
	}	
}

$Properties = [ordered]@{
	TimeGenerated = Get-Date ([datetime]::UtcNow) -Format O
    GlobalStatus           					= $Global_Status
    DeviceName           					= $DeviceName
    SerialNumber           					= $Serial_Number
    Manufacturer           					= $Manufacturer
    ModelFriendlyName      					= $ModelFriendlyName
    Model           						= $Model
    ModelMTM         						= $MTM_Model
    BIOSVersion           					= $Get_Current_BIOS_Version
    SMBIOSBIOSVersion           			= $SMBIOSBIOSVersion
    BIOSReleaseDate           				= $BIOS_Release_Date
    BIOSReleaseDateDaysOld           		= $BIOS_ReleaseDate_Days_Old
    OSVersion           					= $OSVersion
    OS_Build           						= $OS_Build
    OSInstallDate           				= $OS_InstallDate
    DeviceUptime           					= $Device_Uptime
    BootUptimeDays           				= $Boot_Uptime_Days
    IsSecureBootEnabled           			= $Is_SecureBoot_Enabled
    CertActiveDB           					= $Cert_ActiveDB
    CertDefaultDB           				= $Cert_DefaultDB
    CertDefaultDBStatus           			= $Cert_DefaultDB_Status
    HighConfidenceOptOut_Value           	= $HighConfidenceOptOut_Value
    MicrosoftUpdateManagedOptIn_Value       = $MicrosoftUpdateManagedOptIn_Value
    AvailableUpdates_Value           		= $AvailableUpdates_Value
    AvailableUpdates_Convert_Hex           	= $AvailableUpdates_Convert_Hex
    UEFICA2023Status           				= $UEFICA2023Status_Value
    UEFICA2023Status_Label           		= $UEFICA2023Status_Label
    WindowsUEFICA2023Capable           		= $WindowsUEFICA2023Capable_Value
    UEFICA2023Error_Value           		= $UEFICA2023Error_Value
    SecureBootTaskStatus           			= $secureBoot_Task_Status
    SecureBootTaskEnabled           		= $secureBoot_Task_Enabled
    LatestEventId              				= $latestEventId
    BucketId                   				= $bucketId
    Confidence                 				= $confidence
    SkipReasonKnownIssue       				= $skipReasonKnownIssue  # KI_<number> from SkipReason in BucketId event
    Event1801Count             				= $event1801Count
    Event1808Count             				= $event1808Count
    Event1795Count             				= $event1795Count# Firmware returned error
    Event1795ErrorCode         				= $event1795ErrorCode   # Error code from firmware
    Event1796Count             				= $event1796Count          # Error code logged
    Event1796ErrorCode         				= $event1796ErrorCode      # Captured error code
    Event1800Count             				= $event1800Count          # Reboot needed (NOT an error)
    RebootPending              				= $rebootPending           # True if Event 1800 present
    Event1802Count             				= $event1802Count          # Known firmware issue
    KnownIssueId               				= $knownIssueId            # KI_<number> from SkipReason
    Event1803Count             				= $event1803Count          # Missing KEK update
    MissingKEK                 				= $missingKEK              # OEM needs to supply PK signed KEK
}

$Json_Result = ConvertTo-Json -InputObject @([pscustomobject]$Properties) -Depth 100

Add-Type -AssemblyName System.Web

$scope = [System.Web.HttpUtility]::UrlEncode("https://monitor.azure.com//.default")   
$body = "client_id=$appId&scope=$scope&client_secret=$appSecret&grant_type=client_credentials";
$headers = @{"Content-Type" = "application/x-www-form-urlencoded" };
$uri = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
$bearerToken = (Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers).access_token

$headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
$uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2023-01-01";
$uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $Json_Result -Headers $headers -ContentType 'application/json';