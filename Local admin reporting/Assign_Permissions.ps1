#*******************************************************
# Part to fill
$TenantID=""
$DisplayNameOfMSI="" 
#
#*******************************************************

$Permissions = @(
    'DeviceManagementManagedDevices.Read.All'
    'Device.Read.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementConfiguration.ReadWrite.All'
)

# Install the module (You need admin on the machine)
If(!(Get-Installedmodule AzureAD))
	{
		Install-Module AzureAD 	
	}
Else
	{
		Import-Module AzureAD 	
	}

Connect-AzureAD -TenantId $TenantID 
$MSI = (Get-AzureADServicePrincipal -Filter "displayName eq '$DisplayNameOfMSI'")
$MSI_ID = $MSI.ObjectId

$GraphServicePrincipal = Get-AzureADServicePrincipal -SearchString "Microsoft Graph" | Select-Object -first 1
$GraphServicePrincipal_ID = $GraphServicePrincipal.ObjectId
foreach($Permission in $Permissions)
{
    $AppRole = $GraphServicePrincipal.AppRoles | Where-Object {$_.Value -eq $Permission -and $_.AllowedMemberTypes -contains "Application"}
	New-AzureAdServiceAppRoleAssignment -ObjectId $MSI_ID -PrincipalId $MSI_ID -ResourceId $GraphServicePrincipal_ID -Id $AppRole.Id
}