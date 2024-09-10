# Info about DCE, DCR
$DcrImmutableId = "" # id available in DCR > JSON view > immutableId
$DceURI = "" # available in DCE > Logs Ingestion value

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

$Warranty_Array = @()
$Table = "LenovoWarranty_CL" # custom log to create

$URL = "https://download.lenovo.com/bsco/public/allModels.json"
$Get_Models = Invoke-RestMethod -Uri $URL -Method GET
$TimeGenerated = Get-Date ([datetime]::UtcNow) -Format O

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
        $serialNumber = $Device.serialNumber
        $Device_userDisplayName = $Device.userDisplayName        

        $Get_MTM = $Device_Model.Substring(0,4)                            
        $Current_Model = ($Get_Models | where-object {($_ -like "*$Get_MTM*") -and ($_ -notlike "*-UEFI Lenovo*") -and ($_ -notlike "*dTPM*") -and ($_ -notlike "*Asset*") -and ($_ -notlike "*fTPM*")})[0]
        $Device_Model = ($Current_Model.name.split("("))[0]  
        $Device_Model = $Device_Model.trim()   

		$Device_Info = invoke-restmethod "https://pcsupport.lenovo.com/us/en/api/v4/mse/getproducts?productId=$serialNumber"
		$Device_ID = $Device_Info.id
		$Warranty_url = "https://pcsupport.lenovo.com/us/en/products/$Device_ID/warranty"

		$Web_Response = Invoke-WebRequest -Uri $Warranty_url -Method GET

		If($Web_Response.StatusCode -eq 200){
			$HTML_Content = $Web_Response.Content

			$Pattern_Status = '"warrantystatus":"(.*?)"'
			$Pattern_Status2 = '"StatusV2":"(.*?)"'
			$Pattern_StartDate = '"Start":"(.*?)"'
			$Pattern_EndDate = '"End":"(.*?)"'
			
			$Status_Matches = [regex]::Matches($HTML_Content, $Pattern_Status)
			$Statusv2_Matches = [regex]::Matches($HTML_Content, $Pattern_Status2)	
			$StartDate_Matches = [regex]::Matches($HTML_Content, $Pattern_StartDate)
			$EndDate_Matches = [regex]::Matches($HTML_Content, $Pattern_EndDate)

			If($Status_Matches.Count -gt 0){
				$Status_Result = $Status_Matches[0].Groups[1].Value.Trim()
			}Else {
				$Status_Result = "Can not get info"
			}
			
			If($Statusv2_Matches.Count -gt 0){
				$Statusv2_Result = $Statusv2_Matches[0].Groups[1].Value.Trim()
			}Else {
				$Statusv2_Result = "Can not get info"
			}	
			
			If($StartDate_Matches.Count -gt 0){
				$StartDate_Result = $StartDate_Matches[0].Groups[1].Value.Trim()
			}

			If($EndDate_Matches.Count -gt 0){
				$EndDate_Result = $EndDate_Matches[0].Groups[1].Value.Trim()
			}
		}

        $Obj = New-Object PSObject
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "TimeGenerated" -Value $TimeGenerated	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "DeviceName" -Value $Device_Name	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "ModelMTM" -Value $Get_MTM	
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "ModelFamilyname" -Value $Device_Model	        
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "SN" -Value $serialNumber
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "User" -Value $Device_userDisplayName		
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "Status" -Value $Status_Result
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "StartDate" -Value $StartDate_Result
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "EndDate" -Value $EndDate_Result
        Add-Member -InputObject $Obj -MemberType NoteProperty -Name "IsActive" -Value $Statusv2_Result
		$Warranty_Array += $Obj
    }

$Warranty_Array_Devices = $Warranty_Array | where {($_.Status -ne "Can not get info")}
ForEach($Device in $Warranty_Array_Devices)
    {
        $body = $Device | ConvertTo-Json -AsArray;
        $headers = @{"Authorization" = "Bearer $bearerToken"; "Content-Type" = "application/json" };
        $uri = "$DceURI/dataCollectionRules/$DcrImmutableId/streams/Custom-$Table"+"?api-version=2023-01-01";
        $uploadResponse = Invoke-RestMethod -Uri $uri -Method "Post" -Body $body -Headers $headers;           
    }  
   