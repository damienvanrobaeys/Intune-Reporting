#************************************************************************************************************************
# 												Part to fill
#************************************************************************************************************************
$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$LogType = "DiskSize_CL" # Custom log to create in lo Analytics
$TimeStampField = "" # let to blank
#************************************************************************************************************************

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

add-type -type  @"
	using System;
	using System.Runtime.InteropServices;
	using System.ComponentModel;
	using System.IO;

	namespace Disk
	{
		public class Size
		{				
			[DllImport("kernel32.dll")]
			static extern uint GetCompressedFileSizeW([In, MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
			out uint lpFileSizeHigh);
						
			public static ulong SizeOnDisk(string filename)
			{
			  uint High_Order;
			  uint Low_Order;
			  ulong GetSize;

			  FileInfo CurrentFile = new FileInfo(filename);
			  Low_Order = GetCompressedFileSizeW(CurrentFile.FullName, out High_Order);
			  int GetError = Marshal.GetLastWin32Error();

			 if (High_Order == 0 && Low_Order == 0xFFFFFFFF && GetError != 0)
				{
					throw new Win32Exception(GetError);
				}
			 else 
				{ 
					GetSize = ((ulong)High_Order << 32) + Low_Order;
					return GetSize;
				}
			}
		}
	}
"@

Function OD_SizeOnDisk
	{
		param(
		$Folder_to_check	
		)	

		$Global:Get_All_Files = Get-ChildItem $Folder_to_check -recurse -ea silentlycontinue | Where-Object {! $_.PSIsContainer} 
		$OD_Files_Array = @()
		ForEach($File in $Get_All_Files)  
			{
				If((test-path $File.FullName))
					{
						$SizeOnDisk = [Disk.Size]::SizeOnDisk($File.FullName) 						
						$total_SizeOnSisk +=  $SizeOnDisk
						$total_size +=  $File.Length									
						$Return_Array = $total_size, $total_SizeOnSisk
					}
			}
		return $Return_Array				
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

$WMI_computersystem = gwmi win32_computersystem
$Manufacturer = $WMI_computersystem.manufacturer
If($Manufacturer -eq "lenovo")
	{
		$Get_Current_Model = $WMI_computersystem.SystemFamily			
	}Else{
		$Get_Current_Model = $WMI_computersystem.Model		
	}		
	
$WindowsOld_Path = "C:\Windows.old"
If(test-path $WindowsOld_Path)
	{
		$WindowsOld = GetSizeContent -Item_Path $WindowsOld_Path		
		$WindowsOld_SizeFormated = $WindowsOld[0]
		$WindowsOld_Size = $WindowsOld[1]
	}
	
$ccmcache_Path = "C:\Windows\ccmcache"
If(test-path $ccmcache_Path)
	{
		$ccmcache = GetSizeContent -Item_Path $ccmcache_Path		
		$ccmcache_SizeFormated = $ccmcache[0]
		$ccmcache_Size = $ccmcache[1]
	}
		
$SoftwareDistribution_Path = "C:\Windows\SoftwareDistribution\Download"
If(test-path $SoftwareDistribution_Path)
	{
		$SoftwareDistribution = GetSizeContent -Item_Path $SoftwareDistribution_Path		
		$SoftwareDistribution_SizeFormated = $SoftwareDistribution[0]
		$SoftwareDistribution_Size = $SoftwareDistribution[1]
	}

$Windows_Logs_Path = "C:\windows\Logs"
If(test-path $Windows_Logs_Path)
	{
		$WindowsLogs = GetSizeContent -Item_Path $Windows_Logs_Path		
		$WindowsLogs_SizeFormated = $WindowsLogs[0]
		$WindowsLogs_Size = $WindowsLogs[1]
	}

$Windows_Temp_Path = "C:\windows\temp"
If(test-path $Windows_Temp_Path)
	{
		$WindowsTemp = GetSizeContent -Item_Path $Windows_Temp_Path		
		$WindowsTemp_SizeFormated = $WindowsTemp[0]
		$WindowsTemp_Size = $WindowsTemp[1]
	}
	
$ProgramData_Path = "C:\ProgramData"
If(test-path $ProgramData_Path)
	{
		$ProgramData = GetSizeContent -Item_Path $ProgramData_Path		
		$ProgramData_SizeFormated = $ProgramData[0]
		$ProgramData_Size = $ProgramData[1]
	}	
	
$LiveKernelReports_Folder = "$env:windir\LiveKernelReports"
If(test-path $LiveKernelReports_Folder)
	{
		$KernelReports = GetSizeContent -Item_Path $LiveKernelReports_Folder		
		$KernelReports_SizeFormated = $KernelReports[0]
		$KernelReports_Size = $KernelReports[1]
	}

$Memory_DMP_File = "$env:windir\memory.dmp"
If(test-path $Memory_DMP_File)
	{
		$MemoryDMP = GetSizeContent -Item_Path $Memory_DMP_File		
		$MemoryDMP_SizeFormated = $MemoryDMP[0]
		$MemoryDMP_Size = $MemoryDMP[1]	
	}

$minidump_Folder = "$env:windir\minidump"
If(test-path $minidump_Folder)
	{
		$minidump = GetSizeContent -Item_Path $minidump_Folder
		$minidump_SizeFormated = $minidump[0]
		$minidump_Size = $minidump[1]
	}

$WinSxS_Folder = "$env:SystemRoot\WinSxS"
If(test-path $WinSxS_Folder)
	{
		$Winsxs = GetSizeContent -Item_Path $WinSxS_Folder
		$Winsxs_SizeFormated = $Winsxs[0]
		$Winsxs_Size = $Winsxs[1]
	}
	
$User_CrashDumps_Path = "$env:userprofile\AppData\Local\CrashDumps"
If(test-path $User_CrashDumps_Path)
	{
		$Crashdumps = GetSizeContent -Item_Path $User_CrashDumps_Path
		$Crashdumps_SizeFormated = $Crashdumps[0]
		$Crashdumps_Size = $Crashdumps[1]
	}

$UserTemp_Folder = "$env:userprofile\AppData\Local\Temp"
If(test-path $UserTemp_Folder)
	{
		$UserTemp = GetSizeContent -Item_Path $UserTemp_Folder
		$UserTemp_SizeFormated = $UserTemp[0]
		$UserTemp_Size = $UserTemp[1]
	}	
	
$Downloads_Folder = "$env:userprofile\Downloads"
If(test-path $Downloads_Folder)
	{
		$Download = GetSizeContent -Item_Path $Downloads_Folder
		$Download_SizeFormated = $Download[0]
		$Download_Size = $Download[1]
		$Download_SizeOnDisk_Percent = '{0:N0}' -f (($Download_Size / $Disk_Full_Size * 100),1)	
	}	
	
	
# Get Hard disk size info
$Win32_LogicalDisk = Get-ciminstance Win32_LogicalDisk | where {$_.DeviceID -eq "C:"}
$Disk_Full_Size = $Win32_LogicalDisk.size
$Disk_Free_Space = $Win32_LogicalDisk.Freespace

$Total_size_NoFormat = [Math]::Round(($Disk_Full_Size))
$Free_size_formated = Format_Size -size $Disk_Free_Space
$Total_size_formated = Format_Size -size $Disk_Full_Size
[int]$Free_Space_percent = '{0:N0}' -f (($Disk_Free_Space / $Total_size_NoFormat * 100),1)

$OD_Folder_Path = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1").UserFolder
$OD_Main_Size = (OD_SizeOnDisk -Folder_to_check $OD_Folder_Path)
$OD_SizeDisk = $OD_Main_Size[1]
$OD_FullSize = $OD_Main_Size[0]			
	
$Format_OD_FullSize = Format_Size -size $OD_FullSize
$Format_OD_SizeDisk = Format_Size -size $OD_SizeDisk	
$ODUsedSpaceOnDisk = [Math]::round((($OD_FullSize/$Total_size_NoFormat) * 100),2)


# Getting documents folder size
$Documents_Path = [System.Environment]::GetFolderPath("MyDocuments")
If($Documents_Path -like "*OneDrive*")
{
	$Documents_Size = (OD_SizeOnDisk -Folder_to_check $Documents_Path)
	$Documents_FullSize = $Documents_Size[0]	
	$Documents_SizeOnDisk = $Documents_Size[1]	
	$Documents_FullSize_Formated = Format_Size -size $Documents_FullSize		
	$Documents_SizeOnDisk_Formated = Format_Size -size $Documents_SizeOnDisk		
}Else{
	$Documents_Size = GetSizeContent -Item_Path $Documents_Path
	$Documents_FullSize = $Documents_Size[1]		
	$Documents_SizeOnDisk = $Documents_Size[1]			
	$Documents_FullSize_Formated = $Documents_Size[0]
	$Documents_SizeOnDisk_Formated = $Documents_Size[0]	
}	

# Getting desktop folder size
$Desktop_Path = [System.Environment]::GetFolderPath("Desktop")
If($Desktop_Path -like "*OneDrive*")
{
	$Desktop_Size = (OD_SizeOnDisk -Folder_to_check $Desktop_Path)	
	$Desktop_FullSize = $Desktop_Size[0]		
	$Desktop_SizeOnDisk = $Desktop_Size[1]		
	$Desktop_FullSize_Formated = Format_Size -size $Desktop_FullSize
	$Desktop_SizeOnDisk_Formated = Format_Size -size $Desktop_SizeOnDisk
	
}Else{
	$Desktop_Size = GetSizeContent -Item_Path $Desktop_Path
	$Desktop_FullSize = $Desktop_Size[1]		
	$Desktop_SizeOnDisk = $Desktop_Size[1]			
	$Desktop_FullSize_Formated = $Desktop_Size[0]
	$Desktop_SizeOnDisk_Formated = $Desktop_Size[0]	
}	

# Getting desktop folder size
$Pictures_Path = [System.Environment]::GetFolderPath("MyPictures")
If($Pictures_Path -like "*OneDrive*")
{
	$Pictures_Size = (OD_SizeOnDisk -Folder_to_check $Pictures_Path)
	$Pictures_FullSize = $Pictures_Size[0]		
	$Pictures_SizeOnDisk = $Pictures_Size[1]		
	$Pictures_FullSize_Formated = Format_Size -size $OD_Pictures_FullSize
	$Pictures_SizeOnDisk_Formated = Format_Size -size $Get_OD_Pictures_SizeOnDisk			
}Else{
	$Pictures_Size = GetSizeContent -Item_Path $Pictures_Path
	$Pictures_FullSize = $Pictures_Size[1]		
	$Pictures_SizeOnDisk = $Pictures_Size[1]			
	$Pictures_FullSize_Formated = $Pictures_Size[0]
	$Pictures_SizeOnDisk_Formated = $Pictures_Size[0]	
}	


# Getting size of the recycle bin
$Recycle_Bin_Size = (Get-ChildItem -LiteralPath 'C:\$Recycle.Bin' -File -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
$RecycleBin_size_Percent = '{0:N0}' -f (($Recycle_Bin_Size / $Disk_Full_Size * 100),1)	
$Formated_RecycleBin_size = (Format_Size -size $Recycle_Bin_Size)	


# Check if Always keep on this device is selected at OneDrive root
$Get_OD_Attribute = (Get-Item $OD_Folder_Path).Attributes
If($Get_OD_Attribute -like "525*")
	{
		$Always_Keep_device = "Yes"
	}Else{
		$Always_Keep_device = "No"
	}	


# Get larger folders in C:\Users
$MostWanted_Folders_Users = @()
$Folders_In_Users = ""
$Get_Users_Directories = Get-ChildItem "C:\Users" -Directory -ea SilentlyContinue
foreach ($Directory in $Get_Users_Directories) {
    $Dir_FullName = $Directory.FullName
    $Directory_Size_OnDisk = (Get-ChildItem -Path $Dir_FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
	$Directory_Formated_Size = Format_Size -size $Directory_Size_OnDisk	
    If($Directory_Size_OnDisk -gt 0) {
        $Obj = [PSCustomObject]@{
            Path     = $Dir_FullName
            Size     = $Directory_Formated_Size
            FullSize = $Directory_Size_OnDisk
        }
        $MostWanted_Folders_Users += $Obj
		$Folders_In_Users += "$Dir_FullName ($Directory_Formated_Size)`n"		
    }
}


# Get larger folders at root of C:
$MostWanted_Folders_C = @()
$Get_C_Directories = Get-ChildItem "C:\" | Where-Object{(($_.PSIsContainer) -and ($_.name -ne "Users"))}
foreach ($Directory in $Get_C_Directories) {
    $Dir_FullName = $Directory.FullName
    $Directory_Size_OnDisk = (Get-ChildItem -Path $Dir_FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
	$Directory_Formated_Size = Format_Size -size $Directory_Size_OnDisk	
    If($Directory_Size_OnDisk -gt 0) {
        $Obj = [PSCustomObject]@{
            Path     = $Dir_FullName
            Size     = $Directory_Formated_Size
            FullSize = $Directory_Size_OnDisk
        }
        $MostWanted_Folders_C += $Obj
		$Folders_In_C += "$Dir_FullName ($Directory_Formated_Size)`n"		
    }
}


# Get larger folders in C:\ProgramData
$MostWanted_Folders_ProgramData = @()
$Get_ProgramData_Directories = Get-ChildItem "C:\ProgramData" | Where-Object{(($_.PSIsContainer))}
foreach ($Directory in $Get_ProgramData_Directories) {
    $Dir_FullName = $Directory.FullName
    $Directory_Size_OnDisk = (Get-ChildItem -Path $Dir_FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
	$Directory_Formated_Size = Format_Size -size $Directory_Size_OnDisk	
    If($Directory_Size_OnDisk -gt 0) {
        $Obj = [PSCustomObject]@{
            Path     = $Dir_FullName
            Size     = $Directory_Formated_Size
            FullSize = $Directory_Size_OnDisk
        }
        $MostWanted_Folders_ProgramData += $Obj
    }
}
$Top_10_Folders_ProgramData = $MostWanted_Folders_ProgramData | Sort-Object -Property FullSize -Descending | Select-Object -First 10
foreach($Folder in $Top_10_Folders_ProgramData) 
{
	$Folder_Path = $Folder.Path
	$Folder_Size = $Folder.Size			
	$Folders_In_ProgramData += "$Folder_Path ($Folder_Size)`n"
}		


# Get larger folders in OneDrive
# $OD_Folder_Path = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1").UserFolder
$Get_OD_Folders = Get-ChildItem $OD_Folder_Path -ea silentlycontinue | Where-Object {$_.PSIsContainer} 
$OD_Folders_Array = @()
$total_disk_size = ""
$total_size = ""
$Folders_In_OD = ""
$OD_Obj = ""

[int64]$total_disk_size = 0
[int64]$total_size = 0

foreach ($Directory in $Get_OD_Folders) {
    $Dir_FullName = $Directory.FullName

    $Main_Size = OD_SizeOnDisk -Folder_to_check $Dir_FullName

    If($null -eq $Main_Size -or $Main_Size.Count -lt 2) {
        continue
    }

    $Directory_Size = $Main_Size[0]
    $Directory_Size_OnDisk = $Main_Size[1]
    $Directory_Formated_Size = Format_Size -size $Directory_Size_OnDisk

    If($Directory_Size -gt 0) {
        $Obj = [PSCustomObject]@{
            Path        = $Dir_FullName
            FullSize    = $Directory_Size_OnDisk
            Size        = $Directory_Formated_Size			
        }
        $OD_Folders_Array += $Obj
    }
}
$Top_10_Folders_OneDrive = $OD_Folders_Array | Sort-Object -Property FullSize -Descending | Select-Object -First 10
foreach($Folder in $Top_10_Folders_OneDrive) 
{
	$Folder_Path = $Folder.Path
	$Folder_Size = $Folder.SizeOnDisk		
	$Folder_Size = $Folder.Size				
	$Folders_In_OD += "$Folder_Path ($Folder_Size)`n"
}	


# Get PST size if found
$Check_Outlok_Process = Get-Process Outlook
If($Check_Outlok_Process -eq $null)
	{
		$outlook = New-Object -comobject Outlook.Application 	
	}Else{
		$outlook = [Runtime.InteropServices.Marshal]::GetActiveObject("Outlook.Application")
	}

$PST_Files = ""
$Script:User_All_PST_Files = $outlook.Session.Stores | where {($_.FilePath -like '*.PST')} 
If($User_All_PST_Files -ne $null)
	{
		$All_PST = $User_All_PST_Files | select displayname, filepath
		$PST_result = @()
		ForEach($PST in $All_PST)
			{
				$PST_Path = $PST.filepath
				$PST_Size = GetSizeContent -Item_Path $PST_Path
				$PST_SizeFormated = $PST_Size[0]
				$PST_Size = $PST_Size[1]

				$Obj = [PSCustomObject]@{
					Path     = $PST_Path
					Size     = $PST_SizeFormated
					FullSize = $PST_Size
				}
				$PST_result += $Obj
				$PST_Files += "$PST_Path`n"	
				$PST_Total_Size += $PST_Size
			}
		$PST_count = $PST_result.count
		$PST_Total_Size_Formated = Format_Size -size $PST_Total_Size	
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
    "PSTTotalSizeFormated"         = $PST_Total_Size_Formated	
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

	"TopUsersFoldersArray"         = $MostWanted_Folders_Users	
    "TopUsersFoldersText"          = $Folders_In_Users	
	
    "Top10CFoldersArray"           = $MostWanted_Folders_C		
    "Top10CFoldersText"            = $Folders_In_C	
		
    "Top10ProgramDataFoldersArray" = $Top_10_Folders_ProgramData		
    "Top10ProgramDataFoldersText"  = $Folders_In_ProgramData		

    "Top10ODFoldersArray"          = $Top_10_Folders_OneDrive
    "Top10ODFoldersText"           = $Folders_In_OD	
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
	