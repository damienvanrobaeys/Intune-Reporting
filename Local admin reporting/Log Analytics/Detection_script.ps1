#**************************** Part to fill ************************************
# Log analytics part
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$LogType = "LocalAdminReport" # Custom log to create in lo Analytics
$TimeStampField = "" # let to blank
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
	}
Else
	{
		$Get_Current_Model = $WMI_computersystem.Model		
	}

# Getting local admin accounts
$Get_Local_AdminGroup = Gwmi win32_group -Filter "Domain='$env:computername' and SID='S-1-5-32-544'"
$Get_Local_AdminGroup_Name = $Get_Local_AdminGroup.Name
$Get_Administrator_Name = $Get_Local_AdminGroup_Name -replace ".$"	
$Authorized_Accounts += $Get_Administrator_Name

#*************************************************************************************************
# In this part we will add authorized accounts meaning accounts that may be in the local admin group
# In my case I added below roles from Azure:
# - Azure AD role: Global administrator (ID: b6521684-d479-4ca2-8a98-7c08018e68d5)
# - Azure AD role: Azure AD Joined Device Local Administrator (ID: de9ed3ae-b288-4f05-99d0-785e0e47d4d8)
# Get the ID and convert ID to SID, as below:
# - Use this website: https://erikengberg.com/azure-ad-object-id-to-sid/
# - Use this script: https://oliverkieselbach.com/2020/05/13/powershell-helpers-to-convert-azure-ad-object-ids-and-sids/
$Authorized_Accounts = @(
$Get_Administrator_Name; # Built-in admin user account: Administrateur or Administrator... depending of the OS language
)
#*************************************************************************************************

$Local_Admin_Group_Infos = ([ADSI]"WinNT://$env:COMPUTERNAME").psbase.children.find("$Get_Local_AdminGroup_Name")
$Get_Local_AdminGroup_Members = $Local_Admin_Group_Infos.psbase.invoke("Members")

$Local_admin_found = 0
foreach($Member in $Get_Local_AdminGroup_Members) 
{
	$Get_AdminAccount_ADS_Path = $Member.GetType().InvokeMember('Adspath','GetProperty',$null,$Member,$null) 
	$Account_Infos = $Get_AdminAccount_ADS_Path.split('/',[StringSplitOptions]::RemoveEmptyEntries)
	$Other_Local_Admin = $Account_Infos[-1] | Where {($Authorized_Accounts -notcontains $_)}			
	If($Other_Local_Admin -ne $null)
		{
			$Convert_User_to_SID = (New-Object System.Security.Principal.NTAccount("$Other_Local_Admin")).Translate([System.Security.Principal.SecurityIdentifier]).value			

			$Local_admin_found++
			$Get_LocalAdmin_Event = Get-WinEvent -FilterHashtable @{LogName = "Security"; Id = 4732 } -ErrorAction SilentlyContinue | Where-Object { (($_.Message -like "*$Get_Local_AdminGroup_Name*") -and ($_.Message -like "*$Convert_User_to_SID*")) }
			If($Get_LocalAdmin_Event -ne $null)
				{
					$Get_LocalAdmin_Event_Date = $Get_LocalAdmin_Event.TimeCreated
					$Get_LocalAdmin_Event_message = $Get_LocalAdmin_Event.message

					$Event_Message = ((($Get_LocalAdmin_Event_message -split "`n").trim() | select-string -pattern "account")[0])
					$Event_Message = $Event_Message.ToString()
					$Added_by = $Event_Message.split(":")[1].Trim()

					$Account_Info = "Added by $Added_by on $Get_LocalAdmin_Event_Date"		
					$Local_Admin_LA += "$Other_Local_Admin ($Account_Info)`n"							
				}
			Else
				{
					$Local_Admin_LA += "$Other_Local_Admin`n"
				}				
		}				
}	

If($Local_Admin_LA -ne $null)
	{
		$Local_Admin_LA = $Local_Admin_LA.TrimEnd()		
		write-output $Local_Admin_LA
		$Admin_Status = "AdminFound"		
		$Exit_Status = 1
	}
Else
	{
		write-output "NoAdmin"
		$Admin_Status = "NoAdmin"
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
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params
	
If($Exit_Status -eq 1)
	{
		EXIT 1
	}
Else
	{
		EXIT 0
	}	
