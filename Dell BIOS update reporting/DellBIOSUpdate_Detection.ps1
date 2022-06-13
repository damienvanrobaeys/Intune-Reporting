$CustomerId = "" # Log Analytics Workspace ID
$SharedKey = '' # Log Analytics Workspace Primary Key
$LogType = "DellBIOSUpdate" # Custom log to create in lo Analytics
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


$WMI_computersystem = gwmi win32_computersystem
$Manufacturer = $WMI_computersystem.manufacturer
If($Manufacturer -notlike "*dell*")
	{
		write-output "Poste non Dell"	
		EXIT 0	
	}						


$ddlCategoryWeb =[xml]@'
<select id="ddl-category" class="w-100 form-control custom-select drivers-select">
    <option value="BI"> BIOS </option>
</select>
'@

$Script:dictionaryCategory = @{}
$ddlCategoryWeb.select.option | Foreach {$Script:dictionaryCategory[$_.value] = $_.'#text'.Trim()}

$Script:ddlCategoryWeb =[xml]@'
<select id="operating-system" class="w-100 form-control custom-select drivers-select">
	<option value="BIOSA">BIOS</option>
</select>
'@


Class Dell 
{

    
    Static hidden [String]$_vendorName = "Dell"
    hidden [Object[]] $_deviceCatalog 
    hidden [Object[]] $_deviceImgCatalog 

    # Contructor
    Dell()
    {
        $this._deviceCatalog = [Dell]::GetDevicesCatalog()        
    }

    #####################################################################
    # Get all Data from DELL (Gz format)
    #####################################################################
    # https://www.dell.com/support/components/eula/en-us/eula/api
    
    Static hidden [Object[]]GetDevicesCatalog()
    {
        $result = Invoke-WebRequest -Uri "https://www.dell.com/support/home/en-us/api/catalog/autosuggest" -UseBasicParsing -Headers @{
            "method"="GET"
            "authority"="www.dell.com"
            "scheme"="https"
            "cache-control"="max-age=0"
            "upgrade-insecure-requests"="1"
            "accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
            "sec-fetch-site"="none"
            "sec-fetch-mode"="navigate"
            "sec-fetch-user"="?1"
            "sec-fetch-dest"="document"
            "accept-encoding"="gzip, deflate, br"
            "accept-language"="en-US,en;q=0.9"
        }

        $jsonObject = $($result.Content | ConvertFrom-Json) | Select-Object -Property "PN","PC"
        return $jsonObject
    
    }

    #########################################################################
    # Find Model Based on User input
    #########################################################################

    [Object[]]FindModel($userInputModel)
    {
        $SearchResultFormatted = @()
		$userSearchResult = $this._deviceCatalog.Where({$_.PN -eq $userInputModel}) 
	
		foreach($obj in $userSearchResult){
			 
            $SearchResultFormatted += [PSCustomObject]@{
                Name=$obj.PN;
                Guid=$obj.PC;
                Path="/product/$($obj.PC)";
                Image= $(
                     $obj = $this._deviceImgCatalog.Where({$_.Id -eq $obj.PC})
                        if($obj.Image){
                            "https:$($obj.Image)"
                        }else{
                            'https://i.dell.com/is/image/DellContent/content/dam/global-site-design/product_images/esupport/icons/esupport-blank-space-v2.png'
                        }
                    )
            } 
        }
        return $SearchResultFormatted
    }

    #########################################################################
    # Get Json Data for a Dell Device form its GUID
    #########################################################################

    hidden [Object[]] GetModelWebResponse($modelGUID)
    {

        #  ==== For Download  =======
        $modelGzURL = "https://downloads.dell.com/published/data/drivers/$($ModelGUID).gz"		
        $gzContent = Invoke-WebRequest -Uri $modelGzURL -UseBasicParsing -Headers @{
          "method"="GET"
          "authority"="www.dell.com"
          "scheme"="https"
          "cache-control"="max-age=0"
          "upgrade-insecure-requests"="1"
          "accept"="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
          "sec-fetch-site"="none"
          "sec-fetch-mode"="navigate"
          "sec-fetch-user"="?1"
          "sec-fetch-dest"="document"
          "accept-language"="en-US,en;q=0.9"
         }
		 
        # === Convert Stream Data to viewable Content =====
        $data = $gzContent.Content
		
        $memoryStream = [System.IO.MemoryStream]::new()
        $memoryStream.Write($data, 0, $data.Length)
        $memoryStream.Seek(0,0) | Out-Null
		
        $gZipStream = [System.IO.Compression.GZipStream]::new($memoryStream, [System.IO.Compression.CompressionMode]::Decompress)
        $streamReader = [System.IO.StreamReader]::new($gZipStream)
        $xmlModelInputRaw = $streamReader.readtoend()  
		
        # === Parse content =======================
        $xmlModelInput = New-Object -TypeName System.Xml.XmlDocument		
        $xmlModelInput.LoadXml($xmlModelInputRaw)
		
        return $xmlModelInput
    }
    #########################################################################
    # Load All Drivers to exploitable format
    #########################################################################

    hidden [Object[]]LoadDriversFromWebResponse($webresponse)
    {
        $DownloadItemsObj = [Collections.ArrayList]@()

        if($webresponse.Product.Drivers){

            $DownloadItemsRaw = $webresponse.Product.Drivers.Driver | Sort-Object -Property Title
            $DownloadItemsRawGrouped = $DownloadItemsRaw | Group-Object -Property Title

            ForEach ($Itemgroup in $DownloadItemsRawGrouped){
				$item = $Itemgroup.group | Sort-Object -Property LastUpdateDate | Select-Object -Last 1 

                [Array]$ExeFiles = $item.File 
                $current = [PSCustomObject]@{
                    Title =$item.Title;
                    Category=$Script:dictionaryCategory[$item.Category];
                    Class=$item.Type;
                    OperatingSystemKeys=$item.OS.Split(",");
					
                    Files= [Array]($ExeFiles | ForEach-Object { 
                        if($_){
                            [PSCustomObject]@{
                                IsSelected=$false;
                                ID=$item.ID;
                                Name=$_.FileName.Split('/')[-1];
                                Size="$([Math]::Round($_.Size/1MB, 2)) MB";
                                Type=$item.Type;
                                Version=$item.VendorVersion
                                URL="https://dl.dell.com/$($_.FileName)";
                                Priority=$item.Importance ;
                                Date=$item.LastUpdateDate
                            }
                        }
                    })
                }
				
                $DownloadItemsObj.Add($current) | Out-Null
            }

            # ForEach ($Itemgroup in $DownloadItemsRawGrouped){
                # $item = $null
                # if($Itemgroup.Group.Count -ge 2){
                    # $maximum = 0
                    # foreach($vendorVer in $Itemgroup.Group){
					
                        # if($vendorVer.VendorVersion -gt $maximum){
                            # $maximum = $vendorVer.VendorVersion
                            # $item = $vendorVer
                        # }
                    # }
                # }else{
                    # $item = $Itemgroup.Group
					
                # }

                # [Array]$ExeFiles = $item.File 
                # $current = [PSCustomObject]@{
                    # Title =$item.Title;
                    # Category=$Script:dictionaryCategory[$item.Category];
                    # Class=$item.Type;
                    # OperatingSystemKeys=$item.OS.Split(",");
					
                    # Files= [Array]($ExeFiles | ForEach-Object { 
                        # if($_){
                            # [PSCustomObject]@{
                                # IsSelected=$false;
                                # ID=$item.ID;
                                # Name=$_.FileName.Split('/')[-1];
                                # Size="$([Math]::Round($_.Size/1MB, 2)) MB";
                                # Type=$item.Type;
                                # Version=$item.VendorVersion
                                # URL="https://dl.dell.com/$($_.FileName)";
                                # Priority=$item.Importance ;
                                # Date=$item.LastUpdateDate
                            # }
                        # }
                    # })
                # }
				
                # $DownloadItemsObj.Add($current) | Out-Null
            # }
        }
		
        return $DownloadItemsObj
    }
}

$SerialNumber = $((Get-WmiObject -Class Win32_BIOS).SerialNumber).Trim()
$CurrentOS = (gwmi Win32_OperatingSystem).Version

Try
	{
		$System_SKU = $((Get-WmiObject -Class Win32_ComputerSystem).SystemSKUNumber).Trim()
	}
catch 
	{
		Try 
			{
				$System_SKU = $((Get-ItemProperty -Path HKLM:\HARDWARE\DESCRIPTION\System\BIOS).SystemSKU).Trim()
			}
		catch 
			{
				$System_SKU = "Unknown"
			}		
	}



$Current_User_Profile = Get-ChildItem Registry::\HKEY_USERS -ea silentlycontinue | Where-Object { Test-Path "$($_.pspath)\Volatile Environment" } | ForEach-Object { (Get-ItemProperty "$($_.pspath)\Volatile Environment").USERPROFILE }
$Username = $Current_User_Profile.split("\")[2]	

$Chassis = (Get-CimInstance -ClassName Win32_SystemEnclosure).ChassisTypes
$Device_Chassis = [string]$chassis
If($Chassis -eq 9 -or $Chassis -eq 10 -or $Chassis -eq 14 -or $Chassis -eq 8 -or $Chassis -eq 11 -or $Chassis -eq 12 -or $Chassis -eq 18 -or $Chassis -eq 21 -or $Chassis -eq 31 -or $Chassis -eq 32) 
	{
		$Chassis_Type = "Laptop"
	}
else 
	{
		$Chassis_Type = "Desktop"
	}

$BIOS_Version = Get-ciminstance -class win32_bios
$Current_BIOS_Version = $BIOS_Version.SMBIOSBIOSVersion
$Current_BIOS_Version_ID = $Current_BIOS_Version.Split("(")[0]				

$BIOS_release_date = (gwmi win32_bios | select *).ReleaseDate								
$Format_BIOS_release_date = [DateTime]::new((([wmi]"").ConvertToDateTime($BIOS_release_date)).Ticks, 'Local').ToUniversalTime()	

$Get_Current_Date = get-date
$Diff_CurrentBIOS_and_Today = $Get_Current_Date - $Format_BIOS_release_date
$Diff_Today_CurrentBIOS = $Diff_CurrentBIOS_and_Today.Days					
								
$BIOS_Maj_Version = $BIOS_Version.SystemBiosMajorVersion 
$BIOS_Min_Version = $BIOS_Version.SystemBiosMinorVersion 
$Script:Get_Current_BIOS_Version = "$BIOS_Maj_Version.$BIOS_Min_Version"
$Get_Current_BIOS_Version = $Current_BIOS_Version
$Get_Current_BIOS_Version_Formated = [System.Version]$Current_BIOS_Version


$WMI_computersystem = gwmi win32_computersystem
$Get_Current_Model = (($WMI_computersystem).Model)

$BIOS_Ver_Model = "$Get_Current_BIOS_Version ($Get_Current_Model)"

# $Get_Current_Model = "Latitude E7270"
# $Get_Current_Model = "Latitude E5270"
# $Get_Current_Model = "XPS 13 9360"
# $Get_Current_Model = "Latitude 7390"
# $Get_Current_Model = "Latitude 5320"
# $Get_Current_Model = "Precision 5530"
# $Get_Current_Model = "Precision 5540"


$RunspaceScopeVendor = [Dell]::new()
$Search_Model = $RunspaceScopeVendor.FindModel("$Get_Current_Model")
If($Search_Model -ne $null)
	{
		$Get_GUID = $Search_Model.Guid 
		$wbrsp 	= $RunspaceScopeVendor.GetModelWebResponse("$Get_GUID")
		$DriversModeldatas 	= $RunspaceScopeVendor.LoadDriversFromWebResponse($wbrsp) 
		$DriversModelDatasForOsType = [Array]($DriversModeldatas | Where-Object {($_.Title -like "*System BIOS*" )} )		
		$Get_BIOS_Update = $DriversModelDatasForOsType.files  | Where {$_ -like "*EXE*"}
		$Get_New_BIOS_Version = $Get_BIOS_Update.version
		$Get_New_BIOS_Version_Formated = [System.Version]$Get_New_BIOS_Version	
				
		$Get_New_BIOS_Date = $Get_BIOS_Update.Date
		$Get_New_BIOS_ID = $Get_BIOS_Update.ID		
		
		[int]$Get_New_BIOS_Date_Month = $Get_New_BIOS_Date.split("/")[0]
		[int]$Get_New_BIOS_Date_Day = $Get_New_BIOS_Date.split("/")[1]
		[int]$Get_New_BIOS_Date_Year = $Get_New_BIOS_Date.split("/")[2]
		
		If($Get_New_BIOS_Date_month -lt 10)
		{
			$Get_Month = "0$Get_New_BIOS_Date_month"
		}	
		Else
		{
			$Get_Month = "$Get_New_BIOS_Date_month"
		}			

		If($Get_New_BIOS_Date_Day -lt 10)
		{
			$Get_Day = "0$Get_New_BIOS_Date_Day"
		}	
		Else
		{
			$Get_Day = "$Get_New_BIOS_Date_Day"
		}			
		
		$Get_New_BIOS_Date = "$Get_Month/$Get_Day/$Get_New_BIOS_Date_Year"
		
		$Get_Converted_BIOS_Date = [Datetime]::ParseExact($Get_New_BIOS_Date, 'MM/dd/yyyy', $null)	
		# $Is_BIOS_NotUptoDate = ($Get_Current_BIOS_Version -lt $Get_New_BIOS_Version)
		$Is_BIOS_NotUptoDate = ($Get_Current_BIOS_Version_Formated -lt $Get_New_BIOS_Version_Formated)
		
		If($Is_BIOS_NotUptoDate -eq $null)
			{
				$Script:Script_Status = "Error"
				$Script:BIOS_UpToDate = ""
				$Script:BIOS_New_Version = $Get_New_BIOS_Version	
				$Script:BIOSDaysOld = 0										
				$Script:Exit_Status = 0
			}
		ElseIf($Is_BIOS_NotUptoDate -eq $True)
			{
				$BIOSDaysOld = ($Get_Converted_BIOS_Date - $Format_BIOS_release_date).Days
				$Script:Script_Status = "Success"															
				$Script:BIOS_UpToDate = "No"
				$Script:BIOS_New_Version = $Get_New_BIOS_Version			
				$Script:Exit_Status = 1		
			}
		Else
			{
				$Script:Script_Status = "Success"							
				$Script:BIOS_UpToDate = "Yes"
				$Script:BIOS_New_Version = $Get_New_BIOS_Version			
				$Script:Exit_Status = 0	
			}

		If($BIOSDaysOld -ge 1 -and $BIOSDaysOld -lt 180)
			{
				$Diff_Delay = "1_180"
			}	
		ElseIf($BIOSDaysOld -ge 180 -and $BIOSDaysOld -lt 365)
			{
				$Diff_Delay = "180_365"
			}
		ElseIf($BIOSDaysOld -ge 365 -and $BIOSDaysOld -lt 730)
			{
				$Diff_Delay = "365_730"
			}
		ElseIf($BIOSDaysOld -ge 730)
			{
				$Diff_Delay = "730_More"
			}					
	}


# Creating the object to send to Log Analytics custom logs
$Properties = [Ordered] @{
    "ScriptStatus"            = $Script_Status
    "BIOSUpToDate"            = $BIOS_UpToDate
    "ComputerName"            = $env:computername
    "UserName"                = $username
    "SerialNumber"            = $SerialNumber	
    "CurrentOS"            	  = $CurrentOS	
    "SystemSKU"           	  = $System_SKU		
	"ModelFamilyName"    	  = $Get_Current_Model	
	"BIOSCurrentVersion"      = $Get_Current_BIOS_Version	
	"BIOSCurrentVersionFull"  = $Current_BIOS_Version
	"BIOSVersionModel"        = $BIOS_Ver_Model	
	"CurrentBIOSDate" 	      = $Format_BIOS_release_date
	"BIOSNewVersion"          = $BIOS_New_Version
	"BIOSNewDate"             = $Get_Converted_BIOS_Date	
	"GetNewBIOSID"            = $Get_New_BIOS_ID		
	"NotUpdatedSince"         = $BIOSDaysOld		
	"DateDiffDelay"           = $Diff_Delay	
	"BIOSDaysOld"             = $BIOSDaysOld	
	"DiffTodayCurrentBIOS"    = $Diff_Today_CurrentBIOS	
	"ChassisDevice"    	      = $Device_Chassis				
	"ChassisType"    		  = $Chassis_Type		
}

$BIOSUpdateResult = New-Object -TypeName "PSObject" -Property $Properties
# $BIOSUpdateResult
$BIOSUpdateResultJson = $BIOSUpdateResult | ConvertTo-Json
$params = @{
    CustomerId = $customerId
    SharedKey  = $sharedKey
    Body       = ([System.Text.Encoding]::UTF8.GetBytes($BIOSUpdateResultJson))
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

