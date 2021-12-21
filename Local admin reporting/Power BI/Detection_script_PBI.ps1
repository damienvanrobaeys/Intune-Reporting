$Current_User_Profile = Get-ChildItem Registry::\HKEY_USERS | Where-Object { Test-Path "$($_.pspath)\Volatile Environment" } | ForEach-Object { (Get-ItemProperty "$($_.pspath)\Volatile Environment").USERPROFILE }
$Username = $Current_User_Profile.split("\")[2]		
$WMI_computersystem = gwmi win32_computersystem
$Manufacturer = $WMI_computersystem.manufacturer
If($Manufacturer -eq "lenovo")
	{
		$Get_Current_Model = $WMI_computersystem.SystemFamily.split(" ")[1]			
	}Else
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
$Local_Admin_PBI = ""
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
			$Get_LocalAdmin_Event = Get-EventLog Security -InstanceId 4732 -ea silentlycontinue | Where-Object {(($_.Message -like "*$Get_Local_AdminGroup_Name*") -and ($_.Message -like "*$Convert_User_to_SID*"))}
			If($Get_LocalAdmin_Event -ne $null)
				{
					$Get_LocalAdmin_Event_Date = $Get_LocalAdmin_Event.TimeGenerated
					$Get_LocalAdmin_Event_message = $Get_LocalAdmin_Event.message

					$Event_Message = ((($Get_LocalAdmin_Event_message -split "`n").trim() | select-string -pattern "account")[0])
					$Event_Message = $Event_Message.ToString()
					$Added_by = $Event_Message.split(":")[1].Trim()

					$Account_Info = "Added by $Added_by on $Get_LocalAdmin_Event_Date"		
					$Local_Admin_PBI +=  "$Other_Local_Admin ($Account_Info)^"						
				}
			Else
				{
					$Local_Admin_PBI +=  "$Other_Local_Admin^"											
				}				
		}				
}	

$ComputerName = $env:computername

If($Local_Admin_PBI -ne $null)
	{
		$Local_Admin_List = $Local_Admin_PBI.TrimEnd('^')
		$Admin_Status = "AdminFound"				
		write-output "$Get_Current_Model;$Admin_Status;$Local_admin_found;$Local_Admin_List"
		$Exit_Status = 1
	}
Else
	{
		$Admin_Status = "NoAdmin"	
		write-output "NoAdmin"
		$Exit_Status = 0		
	}


If($Exit_Status -eq 1)
	{
		EXIT 1
	}
Else
	{
		EXIT 0
	}	
