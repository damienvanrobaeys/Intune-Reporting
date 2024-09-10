# Your tenant id (in Azure Portal, under Azure Active Directory -> Overview )
$TenantID=""
# Name of the manage identity or enterprise application
$DisplayNameOfMSI="" 
# Permission to set to the managed identity
$Permissions = @('DeviceManagementManagedDevices.Read.All')
# Check if module is installed and if not install it
If(!(Get-Installedmodule Microsoft.Graph.Applications)){Install-Module Microsoft.Graph.Applications}Else{Import-Module Microsoft.Graph.Applications}
# Authenticate
Connect-MgGraph -Scopes Application.Read.All, AppRoleAssignment.ReadWrite.All, RoleManagement.ReadWrite.Directory -TenantId $TenantID
# Get info about the managed identity
$MSI = Get-MgServicePrincipal -Filter "displayName eq '$DisplayNameOfMSI'"
$API = Get-MgServicePrincipal -Filter "displayName eq 'Microsoft Graph'"
# Check permissions to add
$AppRoles = $API.AppRoles | Where-Object {($_.Value -in $Permissions) -and ($_.AllowedMemberTypes -contains "Application")}
# Set permissions
ForEach($Role in $AppRoles){`
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $MSI.Id -PrincipalId $MSI.Id -AppRoleId $Role.Id -ResourceId $API.Id`
}