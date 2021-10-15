#*************************************************************************************************
# Authorized accounts or group
$Authorized_Accounts = @("GSA_EVT-WKST-Administration")
#*************************************************************************************************

$Get_Local_AdminGroup = Gwmi win32_group -Filter "Domain='$env:computername' and SID='S-1-5-32-544'"
$Get_Local_AdminGroup_Name = $Get_Local_AdminGroup.Name
$Get_Administrator_Name = $Get_Local_AdminGroup_Name -replace ".$"	
$Authorized_Accounts += $Get_Administrator_Name

$Local_Admin_Group_Infos = ([ADSI]"WinNT://$env:COMPUTERNAME").psbase.children.find("$Get_Local_AdminGroup_Name")
$Get_Local_AdminGroup_Members = $Local_Admin_Group_Infos.psbase.invoke("Members")

foreach ($Member in $Get_Local_AdminGroup_Members) 
{
	$Get_AdminAccount_ADS_Path = $Member.GetType().InvokeMember('Adspath','GetProperty',$null,$Member,$null) 
	$Account_Infos = $Get_AdminAccount_ADS_Path.split('/',[StringSplitOptions]::RemoveEmptyEntries)
	$Other_Local_Admin = $Account_Infos[-1] | Where {( $Authorized_Accounts -notcontains $_)}			
	If($Other_Local_Admin -ne $null)
		{
			$Local_Admin +=  "$Other_Local_Admin;"			
		}				
}	

If($Local_Admin -ne $null)
	{
		$Local_Admin_List = $Local_Admin.TrimEnd(';')
		write-output $Local_Admin_List
		EXIT 1
	}
Else
	{
		EXIT 0
	}