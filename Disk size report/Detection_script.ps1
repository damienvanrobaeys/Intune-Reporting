#***************************************** Part to fill ***************************************************
# Log analytics part
$CustomerId = ""
$SharedKey = ''
$LogType = "DiskSize"
$TimeStampField = ""
#***********************************************************************************************************

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

		$Get_All_Files = Get-ChildItem $Folder_to_check -recurse -ea silentlycontinue | Where-Object {! $_.PSIsContainer}
		If($Get_All_Files.Count -gt 0)
			{
				$OD_Files_Array = @()
				ForEach($File in $Get_All_Files)  
					{
						If((test-path $File.FullName))
							{
								$SizeOnDisk = [Disk.Size]::SizeOnDisk($File.FullName) 	
								If($Files_Size)
									{
										$OD_Obj = New-Object PSObject
										Add-Member -InputObject $OD_Obj -MemberType NoteProperty -Name "File name" -Value $File.Name
										Add-Member -InputObject $OD_Obj -MemberType NoteProperty -Name "Path" -Value $File.DirectoryName	
										Add-Member -InputObject $OD_Obj -MemberType NoteProperty -Name "Size" -Value $File.Length
										Add-Member -InputObject $OD_Obj -MemberType NoteProperty -Name "Size on Disk" -Value $SizeOnDisk
										$OD_Files_Array += $OD_Obj					
									}
								
								$total_SizeOnSisk +=  $SizeOnDisk
								$total_size +=  $File.Length
								
								$Log_Analytics_TotalSize = ([System.Math]::Round(($total_size) / 1MB, 2))						
								$Log_Analytics_SizeOnSisk = ([System.Math]::Round(($total_SizeOnSisk) / 1MB, 2))
								
								$Return_Array = $total_size, $total_SizeOnSisk, $Log_Analytics_TotalSize, $Log_Analytics_SizeOnSisk
							}
					}
				return $Return_Array				
			}	
		Else
			{
				return 0
			}
	}
	
# Get computer model
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
	

# Get Hard disk size info
$Win32_LogicalDisk = Get-ciminstance Win32_LogicalDisk | where {$_.DeviceID -eq "C:"}
$Disk_Full_Size = $Win32_LogicalDisk.size
$Disk_Free_Space = $Win32_LogicalDisk.Freespace
# Format hard disk size
$Total_size_NoFormat = [Math]::Round(($Disk_Full_Size))
$Free_size_formated = Format_Size -size $Disk_Free_Space
$Total_size_formated = Format_Size -size $Disk_Full_Size
# Hard disk size percent
[int]$Free_Space_percent = '{0:N0}' -f (($Disk_Free_Space / $Total_size_NoFormat * 100),1)
If($Free_Space_percent -le 10)
	{
		$Disk_FreeSpace_State = "Alert"
	}
ElseIf(($Free_Space_percent -gt 10) -and ($Free_Space_percent -lt 20))
	{
		$Disk_FreeSpace_State = "Warning"
	}
ElseIf(($Free_Space_percent -ge 20) -and ($Free_Space_percent -lt 70))
	{
		$Disk_FreeSpace_State = "OK"
	}
ElseIf($Free_Space_percent -ge 70)
	{
		$Disk_FreeSpace_State = "Awesome"
	}

# Hard disk size Log Anaytics format
$Log_Analytics_Disk_Size = (OD_SizeOnDisk -Folder_to_check $Disk_Full_Size)
$Log_Analytics_Disk_Size = ([System.Math]::Round(($Disk_Full_Size) / 1MB, 2))
$Log_Analytics_Disk_FreeSpace = ([System.Math]::Round(($Disk_Free_Space) / 1MB, 2))

# Get Recycle bin size
$Recycle_Bin_Size = (Get-ChildItem -LiteralPath 'C:\$Recycle.Bin' -File -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
$Global:RecycleBin_size_Percent = '{0:N0}' -f (($Recycle_Bin_Size / $Disk_Full_Size * 100),1)	

# Get OneDrive full size and size on disk
$OD_Path = (Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\OneDrive\Accounts\Business1").UserFolder
# Path of main folders: desktop, documents, pictures
$Documents_Path = [System.Environment]::GetFolderPath("MyDocuments")
$Desktop_Path = [System.Environment]::GetFolderPath("Desktop")
$Pictures_Path = [System.Environment]::GetFolderPath("MyPictures")


# get larger folders from C:\Users
$MostWanted_Folders_Users = @()
$Get_Users_Directories = Get-ChildItem "C:\users" -Directory -Recurse -ea silentlycontinue
ForEach($Directory in $Get_Users_Directories)
	{
		$Dir_FullName = $Directory.FullName
		$Directory_Size_OnDisk = (OD_SizeOnDisk -Folder_to_check $Dir_FullName)[1]	
		$Directory_Formated_Size = Format_Size -size $Directory_Size_OnDisk		
		If($Directory_Size_OnDisk -gt 0)
			{
				$Obj = New-Object PSObject
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Path" -Value $Dir_FullName	
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Size" -Value $Directory_Formated_Size
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "FullSize" -Value $Directory_Size_OnDisk				
				$MostWanted_Folders_Users += $Obj				
			}		
	}
$Top_10_Folders_Users = $MostWanted_Folders_Users | Sort-Object -Property FullSize -Descending | Select-Object -First 10
foreach($Folder in $Top_10_Folders_Users) 
{
	$Folder_Path = $Folder.Path
	$Folder_Size = $Folder.Size			
	$Folders_In_Users += "$Folder_Path ($Folder_Size)`n"
}	


# Get larger folders from current user profile
$MostWanted_Folders_UserProfile = @()	
$Current_User_Profile = Get-ChildItem Registry::\HKEY_USERS -ea silentlycontinue | Where-Object { Test-Path "$($_.pspath)\Volatile Environment" } | ForEach-Object { (Get-ItemProperty "$($_.pspath)\Volatile Environment").USERPROFILE }
$Get_CurrentUser_Directories = Get-ChildItem $Current_User_Profile -Directory -Recurse -ea silentlycontinue
ForEach($Directory in $Get_CurrentUser_Directories)
	{
		$Dir_FullName = $Directory.FullName
		$Directory_Size_OnDisk = (OD_SizeOnDisk -Folder_to_check $Dir_FullName)[1]	
		$Directory_Formated_Size = Format_Size -size $Directory_Size_OnDisk		
		If($Directory_Size_OnDisk -gt 0)
			{
				$Obj = New-Object PSObject
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Path" -Value $Dir_FullName	
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Size" -Value $Directory_Formated_Size
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "FullSize" -Value $Directory_Size_OnDisk				
				$MostWanted_Folders_UserProfile += $Obj				
			}		
	}
$Top_10_Folders_UserProfile = $MostWanted_Folders_UserProfile | Sort-Object -Property FullSize -Descending | Select-Object -First 10
foreach($User_Folder in $Top_10_Folders_UserProfile) 
{
	$User_Folder_Path = $User_Folder.Path
	$Uer_Folder_Size = $User_Folder.Size			
	$Folders_In_UserProfile += "$User_Folder_Path ($Uer_Folder_Size)`n"
}	




# Get larger folders from C:
$MostWanted_Folders_C = @()
$Get_C_Directories = Get-ChildItem "C:\" | Where-Object{(($_.PSIsContainer) -and ($_.name -ne "Users"))}
foreach ($Directory in $Get_C_Directories)
	{
		$Dir_Name = $Directory.FullName
		$Folder_Size = (Get-ChildItem $Dir_Name -Recurse -Force | Measure-Object -Property Length -Sum).Sum 2> $null						
		If($Folder_Size -gt 0)
			{
				$Formated_Size = Format_Size -size $Folder_Size									
				$Obj = New-Object PSObject
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Path" -Value $Dir_Name	
				Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Size" -Value $Formated_Size
				$MostWanted_Folders_C += $Obj		
			}
	}
	
$Top_10_Folders_C = $MostWanted_Folders_C | Sort-Object -Property FullSize -Descending | Select-Object -First 10
foreach($Folder in $Top_10_Folders_C) 
{
	$Folder_Path = $Folder.Path
	$Folder_Size = $Folder.Size			
	$Folders_In_C += "$Folder_Path ($Folder_Size)`n"
}		




$OD_Main_Size = (OD_SizeOnDisk -Folder_to_check $OD_Path)
$OD_FullSize = $OD_Main_Size[0]
$OD_SizeDisk = $OD_Main_Size[1]	
# Format disk size
$Formated_OD_FullSize = Format_Size -size $OD_FullSize
$Formated_OD_SizeOnDisk = Format_Size -size $OD_SizeDisk
# OneDrive full size and size on disk Log Anaytics format
$LogAnalytics_OD_FullSize = $OD_Main_Size[2]		
$LogAnalytics_OD_SizeDisk = $OD_Main_Size[3]		
# OneDrive size on disk percent
$ODUsedSpaceOnDisk = [Math]::round((($OD_FullSize/$Total_size_NoFormat) * 100),2)

If($ODUsedSpaceOnDisk -le 10)
	{
		$OneDrive_UseSize_State = "Awesome"
	}
ElseIf(($ODUsedSpaceOnDisk -gt 10) -and ($ODUsedSpaceOnDisk -lt 40)) 
	{
		$OneDrive_UseSize_State = "OK"
	}	
ElseIf(($ODUsedSpaceOnDisk -gt 0) -and ($ODUsedSpaceOnDisk -lt 50)) 
	{
		$OneDrive_UseSize_State = "Warning"
	}		
ElseIf($ODUsedSpaceOnDisk -ge 50)
	{
		$OneDrive_UseSize_State = "Alert"
	}	


$OD_Documents_Size = (OD_SizeOnDisk -Folder_to_check $Documents_Path)
$OD_Documents_FullSize = $OD_Documents_Size[0]	
$LogAnalytics_OD_Documents_FullSize = $OD_Documents_Size[2]		
$Formated_Documents_Size = Format_Size -size $OD_Documents_FullSize		
$Get_OD_Documents_SizeOnDisk = $OD_Documents_Size[1]
$LogAnalytics_OD_Documents_SizeOnDisk = $OD_Documents_Size[3]				
$Formated_Documents_SizeOnDisk = Format_Size -size $Get_OD_Documents_SizeOnDisk		

$OD_Desktop_Size = (OD_SizeOnDisk -Folder_to_check $Desktop_Path)	
$OD_Desktop_FullSize = $OD_Desktop_Size[0]		
$LogAnalytics_OD_Desktop_FullSize = $OD_Desktop_Size[2]						
$Formated_Desktop_Size = Format_Size -size $OD_Desktop_FullSize
$Get_OD_Desktop_SizeOnDisk = $OD_Desktop_Size[1]
$LogAnalytics_OD_Desktop_SizeOnDisk = $OD_Desktop_Size[3]						
$Formated_Desktop_SizeOnDisk = Format_Size -size $Get_OD_Desktop_SizeOnDisk

$OD_Pictures_Size = (OD_SizeOnDisk -Folder_to_check $Pictures_Path)
$OD_Pictures_FullSize = $OD_Pictures_Size[0]		
$LogAnalytics_OD_Pictures_FullSize = $OD_Pictures_Size[2]								
$Formated_Pictures_Size = Format_Size -size $OD_Pictures_FullSize
$Get_OD_Pictures_SizeOnDisk = $OD_Pictures_Size[1]
$LogAnalytics_OD_Pictures_SizeOnDisk = $OD_Pictures_Size[3]								
$Formated_Pictures_SizeOnDisk = Format_Size -size $Get_OD_Pictures_SizeOnDisk		

# Check if Always keep on this device is selected at OneDrive root
$Get_OD_Attribute = (Get-Item $OD_Path).Attributes
If(($Get_OD_Attribute -eq 525360) -or ($Get_OD_Attribute -like "525*"))
	{
		$Always_Keep_device = "Oui"
	}
Else
	{
		$Always_Keep_device = "Non"
	}	
		
# write-output "$Total_size_formated; $Free_size_formated; $Formated_OD_FullSize; $Formated_OD_SizeOnDisk; $Formated_Desktop_Size; $Formated_Desktop_SizeOnDisk; $Formated_Documents_Size; $Formated_Documents_SizeOnDisk; $Formated_Pictures_Size; $Formated_Pictures_SizeOnDisk; $Free_Space_percent %;$ODUsedSpaceOnDisk %; $OD_Path; $Desktop_Path; $Documents_Path; $Pictures_Path; $Always_Keep_device; $Folder_Value_PBI"

# Create the object
$Properties = [Ordered] @{
    "ComputerName"             = $env:computername
    "UserEmail"                = $env:username
    "OneDrivePath"             = $OD_Path
    "DesktopPath"              = $Desktop_Path
    "DocumentsPath"            = $Documents_Path
    "PicturesPath"             = $Pictures_Path	
    "AlwaysKeepDevice"         = $Always_Keep_device		
    "HardDiskSizeMb"           = $Log_Analytics_Disk_Size
    "HardDiskSizeFreeSpaceMb"  = $Log_Analytics_Disk_FreeSpace	
    "OneDriveFullSizeMb"       = $LogAnalytics_OD_FullSize
    "OneDriveSizeOnDiskMb"     = $LogAnalytics_OD_SizeDisk
    "DocumentsSizeMb"          = $LogAnalytics_OD_Documents_FullSize
    "DocumentsSizeOnDiskMb"    = $LogAnalytics_OD_Documents_SizeOnDisk
    "DesktopSizeMb"            = $LogAnalytics_OD_Desktop_FullSize
    "DesktopSizeOnDiskMb"      = $LogAnalytics_OD_Desktop_SizeOnDisk
    "PicturesSizeMb"           = $LogAnalytics_OD_Pictures_FullSize
    "PicturesSizeOnDiskMb"     = $LogAnalytics_OD_Pictures_SizeOnDisk
    "HardDiskFreeSpacePercent" = $Free_Space_percent
    "DiskFreeSpaceState"       = $Disk_FreeSpace_State	
    "ODUsedSizePercent"        = $ODUsedSpaceOnDisk		
    "OneDriveUseSizeState"     = $OneDrive_UseSize_State
    "RecycleBinSize"    	   = $Recycle_Bin_Size			
    "RecycleBinSizePercent"    = $RecycleBin_size_Percent	
    "DeviceModel"   		   = $Get_Current_Model				
    "Top10UsersFolder"         = $Folders_In_Users	
    "Top10CurrentUserFolder"   = $Folders_In_UserProfile			
    "Top10CFolder"             = $Folders_In_C			
}
$ODSize = New-Object -TypeName "PSObject" -Property $Properties




write-output $ODSize

# Submit the data to the API endpoint
$ODSizeJson = $ODSize | ConvertTo-Json
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($ODSizeJson))
    LogType    = $LogType 
}
$LogResponse = Post-LogAnalyticsData @params