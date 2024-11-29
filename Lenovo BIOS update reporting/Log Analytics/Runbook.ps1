# Info about DCE, DCR, Table
$DcrImmutableId = "dcr-" # id available in DCR > JSON view > immutableId
$DceURI = "" # available in DCE > Logs Ingestion value
$Table = "LenovoBIOS_CL" # custom log to create


# Getting a token and authenticating to your tenant using the managed identity
$url = $env:IDENTITY_ENDPOINT  
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$headers.Add("Metadata", "True") 
$body = @{resource='https://graph.microsoft.com/' } 
$script:accessToken = (Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body ).access_token
Connect-AzAccount -Identity
$headers = @{'Authorization'="Bearer " + $accessToken}

$bearerToken = (Get-AzAccessToken -ResourceUrl "https://monitor.azure.com//.default").Token

$Devices_URL = 'https://graph.microsoft.com/beta/deviceManagement/managedDevices?$filter' + "=contains(operatingSystem,'Windows')"
$All_Devices = Invoke-WebRequest -Uri $Devices_URL -Method GET -Headers $Headers -UseBasicParsing 
$All_Devices_JsonResponse = ($All_Devices.Content | ConvertFrom-Json)
$Get_All_Devices = $All_Devices_JsonResponse.value

If($All_Devices_JsonResponse.'@odata.nextLink')
{
    do {
        $URL = $All_Devices_JsonResponse.'@odata.nextLink'
        $All_Devices = Invoke-WebRequest -Uri $URL -Method GET -Headers $Headers -UseBasicParsing 
        $All_Devices_JsonResponse = ($All_Devices.Content | ConvertFrom-Json)
        $Get_All_Devices += $All_Devices_JsonResponse.value
    } until ($null -eq $All_Devices_JsonResponse.'@odata.nextLink')
}

$Devices_Array = @()
$Getting_XML_Info = $False
$Getting_BIOS_Location = $False 
$Getting_BIOS_Version = $False


$URL = "https://download.lenovo.com/bsco/public/allModels.json"
$Get_Models = Invoke-RestMethod -Uri $URL -Method GET
$TimeGenerated = Get-Date ([datetime]::UtcNow) -Format O

$url = "https://download.lenovo.com/cdrt/td/catalogv2.xml"
[xml]$catalog = (New-Object System.Net.WebClient).DownloadString($url)
$Get_Current_Date = get-date

$Lenovo_Devices = $Get_All_Devices | where {(($_.operatingSystem -eq "windows") -and ($_.manufacturer -eq "lenovo"))}

ForEach($Device in $Lenovo_Devices)
    {
        $Device_ID = $Device.id
        $Device_Name = $Device.deviceName
        $Device_enrolledDateTime = $Device.enrolledDateTime
        $Device_lastSyncDateTime = $Device.lastSyncDateTime
        $Device_userPrincipalName = $Device.userPrincipalName
        $Device_model = $Device.model
        $Get_MTM = ($Device_model.SubString(0, 4)).Trim()
        $Device_serialNumber = $Device.serialNumber
        $Device_userDisplayName = $Device.userDisplayName        

        $Get_MTM = $Device_Model.Substring(0,4)                            
        try{
            $Current_Model = ($Get_Models | where-object {($_ -like "*$Get_MTM*") -and ($_ -notlike "*-UEFI Lenovo*") -and ($_ -notlike "*dTPM*") -and ($_ -notlike "*Asset*") -and ($_ -notlike "*fTPM*")})[0]
            $Device_Model = ($Current_Model.name.split("("))[0]  
            $Device_Model = $Device_Model.trim()   
        }
        catch {
            $Current_Model = "Can not get the info"
        } 

        $Current_Device_URL = "https://graph.microsoft.com/beta/deviceManagement/managedDevices/" + $Device_ID + "?`$select=hardwareInformation"
        $Current_Device_Info = Invoke-WebRequest -Uri $Current_Device_URL -Method GET -Headers $Headers -UseBasicParsing 
        $Current_Device_Info_JsonResponse = ($Current_Device_Info.Content | ConvertFrom-Json)
        
        $Device_Current_BIOS = $Current_Device_Info_JsonResponse.hardwareInformation.systemManagementBIOSVersion
        If($Device_Current_BIOS -eq $null)
            {
                $Current_BIOS_Version = "Can not get the info"
            }
        Else
            {
                If($Device_Current_BIOS -like "*.*.*")
                    {
                        $Current_BIOS_Version = $Device_Current_BIOS.split("(").replace(")","")[1]
                        $Current_BIOS_Ver = $Current_BIOS_Version.split(".")
                        $Current_BIOS_Version = $Current_BIOS_Ver[0] + "." + $Current_BIOS_Ver[1]
                        $Current_BIOS_ID = ($Device_Current_BIOS.split("(").replace(")","")[0]).trim()           
                    }
                ElseIf($Device_Current_BIOS -like "*.*")
                    {
                        $Current_BIOS_Version = $Device_Current_BIOS.split("(").replace(")","")[1]
                        $Current_BIOS_ID = ($Device_Current_BIOS.split("(").replace(")","")[0]).trim()           
                    }
                Else
                    {
                        $Current_BIOS_Version = $Device_Current_BIOS
                        $Current_BIOS_ID = $Current_BIOS_Version.trim()
                    }  

                # Get current BIOS date
                $node = $catalog.ModelList.Model | Where-Object { $_.Types.Type -eq "$Get_MTM" }
                $ReadMeUrl = $node.BIOS.'#text'.Replace('.exe','.txt')
                $content = (Invoke-WebRequest -Uri $ReadMeUrl -UseBasicParsing).Content
                If($content -ne $null)
                    {
                        $Get_CurrentID_Line = ((($content -split "`n").trim() | select-string -pattern "$Current_BIOS_ID")[0]).tostring()
                        If(($Get_CurrentID_Line -like "*/*/*"))
                            {
                                $Get_Current_BIOS_Date = ($Get_CurrentID_Line.split(" "))[-1]                
                                If($Get_Current_BIOS_Date -ne $null)
                                    {
                                        $Format_BIOS_release_date = [DateTime]$Get_Current_BIOS_Date
                                        $Diff_CurrentBIOS_and_Today = $Get_Current_Date - $Format_BIOS_release_date
                                        $Diff_Today_CurrentBIOS = $Diff_CurrentBIOS_and_Today.Days
                                        If($Diff_Today_CurrentBIOS -ne $null)
                                            {
                                                If($Diff_Today_CurrentBIOS -ge 1 -and $Diff_Today_CurrentBIOS -lt 180)
                                                    {
                                                        $Current_BIOS_Days_Old_Range = "1_180"
                                                    }	
                                                ElseIf($Diff_Today_CurrentBIOS -ge 180 -and $Diff_Today_CurrentBIOS -lt 365)
                                                    {
                                                        $Current_BIOS_Days_Old_Range = "180_365"
                                                    }
                                                ElseIf($Diff_Today_CurrentBIOS -ge 365 -and $Diff_Today_CurrentBIOS -lt 730)
                                                    {
                                                        $Current_BIOS_Days_Old_Range = "365_730"
                                                    }
                                                ElseIf($Diff_Today_CurrentBIOS -ge 730)
                                                    {
                                                        $Current_BIOS_Days_Old_Range = "730_More"
                                                    }
                                            }                                        
                                    }	                               
                            }
                        Else
                            {
                                $Format_BIOS_release_date = $null
                                $Diff_Today_CurrentBIOS = $null
                                $Get_Current_BIOS_Date = $null
                            }                            
                    }                              
            }

        $WindowsVersion2 = "win10"       
        $CatalogUrl = "https://download.lenovo.com/catalog/$Get_MTM`_$WindowsVersion2.xml"
        try
            {
                [System.Xml.XmlDocument]$CatalogXml = (New-Object -TypeName System.Net.WebClient).DownloadString($CatalogUrl)
                $Getting_XML_Info = $True  
            }
        catch
            {
                $Last_BIOS_Version = "Can not get info"
                $BIOS_Status = "Can not get info"
                $Getting_XML_Info = $False                		
            }

        If($Getting_XML_Info -eq $True)
            {
                $PackageUrls = ($CatalogXml.packages.ChildNodes | Where-Object { $_.category -match "BIOS UEFI" }).location
                If($PackageUrls -eq $null)
                    {
                        $Last_BIOS_Version = "Can not get info"
                        $BIOS_Status = "Can not get info"
                        $Getting_BIOS_Location = $False	                        
                    }
                Else
                    {
                        If($PackageUrls.Count -eq 0)
                            {
                                $Last_BIOS_Version = "Can not get info"
                                $BIOS_Status = "Can not get info"
                                $Getting_BIOS_Location = $False	
                            }                        
                        ElseIf($PackageUrls.Count -eq 1)
                            {
                                [System.Xml.XmlDocument]$PackageXml = (New-Object -TypeName System.Net.WebClient).DownloadString($PackageUrls)		
                                $Getting_BIOS_Location = $True
                            }
                        ElseIf($PackageUrls.Count -gt 1)
                            {
                                $Last_BIOS_Version = "Multiple versions available"
                                $BIOS_Status = "Multiple versions available"    
                                $Getting_BIOS_Location = $False
                            }                    
                    }
            }

        If($Getting_BIOS_Location -eq $True)
            {
                $baseUrl = $PackageUrls.Substring(0,$PackageUrls.LastIndexOf('/')+1)
                $Last_BIOS_Version = $PackageXml.Package.version	
                If($Last_BIOS_Version -eq $null)
                    {
                        $Last_BIOS_Version = "Can not get info"
                        $BIOS_Status = "Can not get info"
                        $Getting_BIOS_Version = $False			
                    }
                Else
                    {
                        $Getting_BIOS_Version = $True
                        If($Last_BIOS_Version -like "*.*.*")
                            {
                                $Last_BIOS_Ver = $Last_BIOS_Version.split(".")
                                $Last_BIOS_Version = $Last_BIOS_Ver[0] + "." + $Last_BIOS_Ver[1]
                            }
                        Else
                            {
                                $Last_BIOS_Version = $Last_BIOS_Version
                            }                          
                    }
            }

        If($Getting_BIOS_Version -eq $True)
            {
                $Get_Current_Date = get-date
                $Last_BIOS_Date = $PackageXml.Package.ReleaseDate 
				$Last_BIOS_Severity = $PackageXml.Package.severity.type
				#f($Last_BIOS_Severity -ne $null)
				#	{
						If($Last_BIOS_Severity -eq "1")
							{
								$Last_BIOS_Severity_Label = "Critical"
							}
						ElseIf($Last_BIOS_Severity -eq "2")
							{
								$Last_BIOS_Severity_Label = "Recommended"
							}
						Else
							{
								$Last_BIOS_Severity_Label = "Unknown"
							}							
				#	}                
                If($Last_BIOS_Date -ne $null)
                    {
                        Try{
                        $Get_Converted_BIOS_Date = [datetime]::parseexact($Last_BIOS_Date, 'yyyy-MM-dd', $null)
                        }
                        Catch{}
                    }

                $Last_BIOS_Version = $Last_BIOS_Version.trim()

                If($Device_Current_BIOS -ne $null)
                    {
                        $Current_BIOS_Version = $Current_BIOS_Version.trim()
                        If($Last_BIOS_Version -ne $Current_BIOS_Version)
                            {
                                $BIOS_Status = "No"
                                If($Last_BIOS_Date -ne $null)
                                    {
                                        If($Get_Converted_BIOS_Date -ne $null)
                                            {
                                                $Diff_LastBIOS_and_Today = $Get_Current_Date - $Get_Converted_BIOS_Date        
                                                $Diff_in_days = $Diff_LastBIOS_and_Today.Days
                                            }
    
                                    }         
                            }
                        Else 
                            {
                                $BIOS_Status = "Yes"
                            }
                    }
                Else
                    {
                        $BIOS_Status = "Can not get info"
                    }
            }

        $Obj = New-Object PSObject
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "TimeGenerated" -Value $TimeGenerated	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Device" -Value $Device_Name	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "ModelMTM" -Value $Get_MTM	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "ModelFamilyname" -Value $Device_Model	        
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "SN" -Value $Device_serialNumber
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "User" -Value $Device_userPrincipalName
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CurrentBIOSVersion" -Value $Current_BIOS_Version
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CurrentBIOSDate" -Value $Get_Current_BIOS_Date
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CurrentBIOSDateFormat" -Value $Format_BIOS_release_date	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CurrentBIOSDaysOld" -Value $Diff_Today_CurrentBIOS
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "LastBIOSVersion" -Value $Last_BIOS_Version		
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "LastBIOSDate" -Value $Last_BIOS_Date	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "LastBIOSDateFormat" -Value $Get_Converted_BIOS_Date	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "IsUptoDate" -Value $BIOS_Status
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "NewBIOSDaysOld" -Value $Diff_in_days	 
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "CurrentBIOSDaysOldRange" -Value $Current_BIOS_Days_Old_Range
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "LastBIOSSeverity" -Value $Last_BIOS_Severity	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "LastBIOSSeverityLabel" -Value $Last_BIOS_Severity_Label	        	 
        $Devices_Array += $Obj
    }

$BIOS_Update_Status = $Devices_Array | where {($_.IsUptoDate -ne "Can not get info")}
ForEach($Device in $BIOS_Update_Status)
    {
        $body = $Device | ConvertTo-Json -AsArray;
        $body
        # Sending data to Log Analytics Custom Log
        $headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
        $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2023-01-01";
        $uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers;           
    }
