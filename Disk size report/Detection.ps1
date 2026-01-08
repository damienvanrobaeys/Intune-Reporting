##################################################################################################
# 									Variables to fill
##################################################################################################
<#
Set there when to display the alert, 
If the free space perdent on the disk is below alue in variable $Percent_Alert the notification will be displayed
$Percent_Alert = 20
#>

$Percent_Alert = 20

$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$LogType = "DiskSize_CL" # Custom log to create in lo Analytics
$TimeStampField = "" # let to blank
##################################################################################################
# 									Variables to fill
##################################################################################################

# Log analytics functions
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

Function GetSizeContent
	{
		param(
		$Item_Path	
		)
		
		$Size_Array = @()
			
		If(Test-Path $Item_Path) 
			{			
				$Item_Size = (Get-ChildItem -LiteralPath $Item_Path -File -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
				$Item_FormatedSize = Format_Size $Item_Size			

				$total_SizeOnSisk +=  $SizeOnDisk
				$total_size +=  $File.Length									
				$Size_Array = $Item_FormatedSize, $Item_Size
				
				return $Size_Array				
			}			
	}	

Function Format_Size
	{
		param(
		$size	
		)	
		If($size -eq $null){$FormatedSize = "0"}
		ElseIf( $size -lt 1KB ){$FormatedSize = "$("{0:N2}" -f $size) B"}
		ElseIf( $size -lt 1MB ){$FormatedSize = "$("{0:N2}" -f ($size / 1KB)) KB"}
		ElseIf( $size -lt 1GB ){$FormatedSize = "$("{0:N2}" -f ($size / 1MB)) MB"}
		ElseIf( $size -lt 1TB ){$FormatedSize = "$("{0:N2}" -f ($size / 1GB)) GB"}
		ElseIf( $size -lt 1PB ){$FormatedSize = "$("{0:N2}" -f ($size / 1TB)) TB"}
		return $FormatedSize
	}
	
	
# Get Hard disk size info
$Win32_LogicalDisk = Get-ciminstance Win32_LogicalDisk | where {$_.DeviceID -eq "C:"}
$Disk_Full_Size = $Win32_LogicalDisk.size
$Disk_Free_Space = $Win32_LogicalDisk.Freespace
$Total_size_NoFormat = [Math]::Round(($Disk_Full_Size))
[int]$Free_Space_percent = '{0:N0}' -f (($Disk_Free_Space / $Total_size_NoFormat * 100),1)
$Free_size_formated = Format_Size -size $Disk_Free_Space
$Total_size_formated = Format_Size -size $Disk_Full_Size

$WMI_computersystem = gwmi win32_computersystem
$Manufacturer = $WMI_computersystem.manufacturer
If($Manufacturer -eq "lenovo")
	{
		$Get_Current_Model = $WMI_computersystem.SystemFamily			
	}Else{
		$Get_Current_Model = $WMI_computersystem.Model		
	}	

$Documents_Path = [System.Environment]::GetFolderPath("MyDocuments")
$Desktop_Path = [System.Environment]::GetFolderPath("Desktop")
$Pictures_Path = [System.Environment]::GetFolderPath("MyPictures")	

	
 # Check if Always keep on this device is selected at OneDrive root
$OD_Folder_Path = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1").UserFolder
$Get_OD_Attribute = (Get-Item $OD_Folder_Path).Attributes
If($Get_OD_Attribute -like "525*")
	{
		$Always_Keep_device = "Yes"
	}Else{
		$Always_Keep_device = "No"
	}	


# Getting size of the recycle bin
$Recycle_Bin_Size = (Get-ChildItem -LiteralPath 'C:\$Recycle.Bin' -File -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
$RecycleBin_size_Percent = '{0:N0}' -f (($Recycle_Bin_Size / $Disk_Full_Size * 100),1)	
$Formated_RecycleBin_size = (Format_Size -size $Recycle_Bin_Size)	


$Downloads_Folder = "$env:userprofile\Downloads"
If(test-path $Downloads_Folder)
	{
		$Download = GetSizeContent -Item_Path $Downloads_Folder
		$Download_SizeFormated = $Download[0]
		$Download_Size = $Download[1]
		$Download_SizeOnDisk_Percent = '{0:N0}' -f (($Download_Size / $Disk_Full_Size * 100),1)	
	}


# Create the object
$Properties = [Ordered] @{
    "DeviceName"                   = $env:computername
    "DeviceModel"   		       = $Get_Current_Model					
    "UserName"                     = $env:username
	
    "DiskFullSizeMb" 			   = $Disk_Full_Size
    "DiskFreeSpaceMb" 			   = $Disk_Free_Space
    "DiskFullSizeFormated" 		   = $Total_size_formated
    "DiskFreeSpaceFormated" 	   = $Free_size_formated		
    "HardDiskFreeSpacePercent"     = $Free_Space_percent

    "OneDrivePath"             	   = $OD_Folder_Path
    "OneDriveFullSizeMb"           = $OD_FullSize
    "OneDriveSizeOnDiskMb"    	   = $OD_SizeDisk
    "OneDriveSizeOnDiskFormated"   = $Format_OD_SizeDisk
    "OneDriveFullSizeFormated"     = $Format_OD_FullSize	
    "OneDriveUsedSizePercent"      = $ODUsedSpaceOnDisk		
    "AlwaysKeepDevice"             = $Always_Keep_device

    "DesktopPath"                  = $Desktop_Path
    "DocumentsPath"                = $Documents_Path
    "PicturesPath"                 = $Pictures_Path	
	
    "DocumentsSizeMb"          	   = $Documents_FullSize
    "DocumentsSizeOnDiskMb"    	   = $Documents_SizeOnDisk
    "DocumentsSizeFormated"    	   = $Documents_FullSize_Formated
    "DocumentsSizeOnDiskFormated"  = $Documents_SizeOnDisk_Formated

    "DesktopSizeMb"            	   = $Desktop_FullSize
    "DesktopSizeOnDiskMb"      	   = $Desktop_SizeOnDisk
    "DesktopSizeFormated"      	   = $Desktop_FullSize_Formated
    "DesktopSizeOnDiskFormated"    = $Desktop_SizeOnDisk_Formated
	
    "PicturesSizeMb"           	   = $Pictures_FullSize
    "PicturesSizeOnDiskMb"         = $Pictures_SizeOnDisk
    "PicturesSizeFormated"         = $Pictures_FullSize_Formated
    "PicturesSizeOnDiskFormated"   = $Pictures_SizeOnDisk_Formated

    "DownloadSize"   			   = $Download_Size
    "DownloadSizeFormated"         = $Download_SizeFormated
    "DownloadPercentOnDisk"        = $Download_SizeOnDisk_Percent

    "RecycleBinSize"        	   = $Recycle_Bin_Size
    "RecycleBinSizeFormated"       = $Formated_RecycleBin_size
    "RecycleBinPercentOnDisk"      = $RecycleBin_size_Percent

    "UserTempSize"        	   	   = $UserTemp_Size
    "UserTempSizeFormated"         = $UserTemp_SizeFormated

    "PSTCount"         			   = $PST_count
    "PSTTotalSize"         		   = $PST_Total_Size
    "PSTFiles"         			   = $PST_Files

    "ProgramDataSize"              = $ProgramData_Size			
    "WindowsTempSize"              = $WindowsTemp_Size			
    "KernelReportsSize"            = $KernelReports_Size			
    "MemoryDMPSize"                = $MemoryDMP_Size			
    "minidumpSize"                 = $minidump_size			
    "CrashdumpsSize"               = $Crashdumps_size			
    "WinsxsSize"                   = $Winsxs_size			
    "SoftwareDistributionSize"     = $SoftwareDistribution_Size			
    "WindowsOldSize"               = $WindowsOld_Size			
    "WindowsLogsSize"              = $WindowsLogs_Size			
    "ccmcacheSize"                 = $ccmcache_Size			

    "ProgramDataSizeFormated"	   = $ProgramData_SizeFormated				
    "CrashdumpsSizeFormated"	   = $Crashdumps_SizeFormated			
    "WinsxsSizeFormated"           = $Winsxs_SizeFormated			
    "MinidumpSizeFormated"         = $minidump_SizeFormated			
    "MemoryDMPSizeFormated"        = $MemoryDMP_SizeFormated			
    "WindowsTempSizeFormated"      = $WindowsTemp_SizeFormated			
    "KernelReportsSizeFormated"    = $KernelReports_SizeFormated			
    "WindowsOldSizeFormated"       = $WindowsOld_SizeFormated			
    "SoftwareDistribSizeFormated"  = $SoftwareDistribution_SizeFormated			
    "WindowsLogs_SizeFormated"     = $WindowsLogs_SizeFormated			
    "ccmcacheSizeFormated"         = $ccmcache_SizeFormated			

    "TopUsersFolder"        	   = $Folders_In_Users	
    "Top10CFolder"                 = $Folders_In_C		
}

$DiskSize = New-Object -TypeName "PSObject" -Property $Properties

# Submit the data to the API endpoint
$Json = $DiskSize | ConvertTo-Json
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($Json))
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params	
	

If($Free_Space_percent -le $Percent_Alert)
	{
		write-output "Free space percent: $Free_Space_percent"	
		EXIT 1		
	}
Else
	{
		write-output "Free space percent: $Free_Space_percent"	
		EXIT 0
	}