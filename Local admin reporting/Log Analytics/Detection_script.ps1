#**************************** Part to fill ************************************
# Log analytics part
$ResourceGroup = "" # Workgroup associated to Log Analytics Workspace
$WorkspaceName = "" # Log Analytics Workspace name
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$TimeStampField = "" # let to blank
$SubscriptionID = ""
#*******************************************************************************

# Log analytics functions
# More info there: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
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
# More info there: https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
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

# Getting info from device and user
$Current_User_Profile = Get-ChildItem Registry::\HKEY_USERS | Where-Object { Test-Path "$($_.pspath)\Volatile Environment" } | ForEach-Object { (Get-ItemProperty "$($_.pspath)\Volatile Environment").USERPROFILE }
$Username = $Current_User_Profile.split("\")[2]		
$WMI_computersystem = gwmi win32_computersystem
$Manufacturer = $WMI_computersystem.manufacturer
If($Manufacturer -eq "lenovo")
	{
		$Get_Current_Model = $WMI_computersystem.SystemFamily.split(" ")[1]			
	}Else{
		$Get_Current_Model = $WMI_computersystem.Model		
	}


$Current_date = get-date -Format "dddd MM/dd/yyyy HH:mm K"

$Authorized_Accounts = @()
$Local_Admin_LA = @()
$LocalAdmin_Details = @()

$Local_admin_found = 0

$Get_Local_AdminGroup = Gwmi win32_group -Filter "Domain='$env:computername' and SID='S-1-5-32-544'"
$Get_Local_AdminGroup_Name = $Get_Local_AdminGroup.Name
$Get_Administrator_Name = $Get_Local_AdminGroup_Name -replace ".$"	# Built-in admin user account: Administrateur or Administrator
$Get_Administrator_Status = (Get-LocalUser $Get_Administrator_Name).Enabled

#*************************************************************************************************
# In this part we will add authorized accounts meaning accounts that may be in the local admin group
# In my case I added below roles from Azure:
# - Azure AD role: Global administrator (ID: b6521684-d479-4ca2-8a98-7c08018e68d5)
# - Azure AD role: Azure AD Joined Device Local Administrator (ID: de9ed3ae-b288-4f05-99d0-785e0e47d4d8)
# Get the ID and convert ID to SID, as below:
# - Use this website: https://erikengberg.com/azure-ad-object-id-to-sid/
# - Use this script: https://oliverkieselbach.com/2020/05/13/powershell-helpers-to-convert-azure-ad-object-ids-and-sids/

$Authorized_Accounts = @(
)
#*************************************************************************************************

If($Get_Administrator_Status -eq $False)
	{
		$Authorized_Accounts += $Get_Administrator_Name	
	}

$Get_Local_AdminGroup_Members = ([ADSI]"WinNT://./Administrateurs").psbase.Invoke('Members') | % {
 ([ADSI]$_).InvokeGet('AdsPath')
}
$Get_Local_AdminGroup_Members = $Get_Local_AdminGroup_Members -replace "WinNT://",""

foreach($Member in $Get_Local_AdminGroup_Members) 
{
	$Account_Infos = $Member.split("/")
	$Account_Name = $Account_Infos[-1]
	$Other_Local_Admin = $Account_Name | Where {($Authorized_Accounts -notcontains $_)}
	If($Other_Local_Admin -ne $null)
		{
			$Account_Info = Get-LocalUser $Account_Name -ea silentlycontinue
			If($Account_Info -ne $null)
				{
					$Member_Description = $Account_Info.Description
					$PasswordLastSet = $Account_Info.PasswordLastSet		
					$IsEnabled = $Account_Info.Enabled		
					$UserMayChangePassword = $Account_Info.UserMayChangePassword		
					$PasswordRequired = $Account_Info.PasswordRequired		
					$Account_SID = $Account_Info.SID.value		

					If($Member_Description -eq $null)
						{
							$Member_Description = "No description"
						}

					If($IsEnabled -eq $null)
						{
							$IsEnabled = "Null"
						}

					If($PasswordLastSet -eq $null)
						{
							$PasswordLastSet = "Null"
						}
						
					If($UserMayChangePassword -eq $null)
						{
							$UserMayChangePassword = "Null"
						}

					If($PasswordRequired -eq $null)
						{
							$PasswordRequired = "Null"
						}

					If($Account_SID -eq $null)
						{
							$Account_SID = "Null"
						}						
				}
			Else
				{
					$Member_Description = "Cloud account"
					$PasswordLastSet = "Can not get info"	
					$IsEnabled = "Can not get info"			
					$UserMayChangePassword = "Can not get info"			
					$PasswordRequired = "Can not get info"		
					$Account_SID = "Can not get info"						
				}
			
			$Obj = New-Object PSObject
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CurrentDate" -Value $Current_date
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "DeviceName" -Value $env:computername
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Account" -Value $Account_Name
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Description" -Value $Member_Description
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "PasswordLastSet" -Value $PasswordLastSet
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "IsEnabled" -Value $IsEnabled
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "UserMayChangePassword" -Value $UserMayChangePassword
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "IsPasswordRequired" -Value $PasswordRequired
			Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Account_SID" -Value $Account_SID

			$Convert_User_to_SID = (New-Object System.Security.Principal.NTAccount("$Other_Local_Admin")).Translate([System.Security.Principal.SecurityIdentifier]).value

			$Local_admin_found++ 
			$Get_LocalAdmin_Event = Get-EventLog Security -InstanceId 4732 -ea silentlycontinue | Where-Object {(($_.Message -like "*$Get_Local_AdminGroup_Name*") -and ($_.Message -like "*$Convert_User_to_SID*"))}
			If($Get_LocalAdmin_Event -ne $null)
				{
					$Get_LocalAdmin_Event_Date = $Get_LocalAdmin_Event.TimeGenerated
					$Get_LocalAdmin_Event_message = $Get_LocalAdmin_Event.message

					$Event_Message = ((($Get_LocalAdmin_Event_message -split "`n").trim() | select-string -pattern "nom")[0])
					$Event_Message = $Event_Message.ToString()
					$Added_by = $Event_Message.split(":")[1].Trim()

					$Account_Info = "$Added_by;$Get_LocalAdmin_Event_Date"
					$Local_Admin_LA += "$Other_Local_Admin ($Account_Info)`n"
					Add-Member -InputObject $Obj -MemberType NoteProperty -Name "AddedBy" -Value $Added_by
					Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CreationDate" -Value $Get_LocalAdmin_Event_Date
				}
			Else
				{
					$Local_Admin_LA += "$Other_Local_Admin"
					Add-Member -InputObject $Obj -MemberType NoteProperty -Name "AddedBy" -Value "Can not get info"
					Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CreationDate" -Value "Can not get info"
				}
		}
	$LocalAdmin_Details += $Obj
}

If($Local_Admin_LA -ne $null)
	{
		$Local_Admin_LA = $Local_Admin_LA.TrimEnd()		
		$Admin_Status = "AdminFound"				
		write-output "$Get_Current_Model;$Admin_Status;$Local_admin_found;$Local_Admin_List"
		$Exit_Status = 1
	}Else{
		$Admin_Status = "NoAdmin"
		write-output "NoAdmin"
		$Exit_Status = 0
	}

# Creating the object to send to Log Analytics custom logs
$Properties = [Ordered] @{
    "ComputerName"        = $env:computername
    "UserEmail"           = $Username
    "Model"               = $Get_Current_Model
	"LocalAdminStatus"    = $Admin_Status
	"LocalAdmin"          = $Local_Admin_LA	
	"LocalAdminCount"     = $Local_admin_found		
}
$LocalAdminResult = New-Object -TypeName "PSObject" -Property $Properties

$LocalAdminResultJson = $LocalAdminResult | ConvertTo-Json
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($LocalAdminResultJson))
    LogType    = "LocalAdmin_Resume" 
}
$LogResponse = Post-LogAnalyticsData @params

If($Local_admin_found -gt 0)
	{
		$LocalAdmin_Details_ResultJson = $LocalAdmin_Details | ConvertTo-Json
		$params = @{
			CustomerId = $customerId
			SharedKey  = $sharedKey
			Body       = ([System.Text.Encoding]::UTF8.GetBytes($LocalAdmin_Details_ResultJson))
			LogType    = "LocalAdmin_Details" 
		}
		$LogResponse = Post-LogAnalyticsData @params		
	}
		
If($Exit_Status -eq 1)
	{
		EXIT 1
	}
Else
	{
		EXIT 0
	}	