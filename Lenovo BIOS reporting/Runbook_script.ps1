#*******************************************************
# Part to fill
$StorageAccount = ""
$ResourceGroup = ""
$container = ""
$TempFolder = "$env:Temp"
$Script_name = "" # Name of the proactive remediation script
#
#*******************************************************

$url = $env:IDENTITY_ENDPOINT  
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]" 
$headers.Add("X-IDENTITY-HEADER", $env:IDENTITY_HEADER) 
$headers.Add("Metadata", "True") 
$body = @{resource='https://graph.microsoft.com/' } 
$script:accessToken = (Invoke-RestMethod $url -Method 'POST' -Headers $headers -ContentType 'application/x-www-form-urlencoded' -Body $body ).access_token

Connect-AzAccount -Identity

$URL = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts"

$headers = @{'Authorization'="Bearer " + $accessToken}
$Get_script_info = Invoke-WebRequest -Uri $URL -Method GET -Headers $Headers -UseBasicParsing 
$JsonResponse = ($Get_script_info.Content | ConvertFrom-Json).value
$result = $JsonResponse | Where{$_.DisplayName -eq "$Script_name"}

$CSV_Name = "$Script_name.csv"
$CSV_Full_Path = "$env:Temp\$CSV_Name"

$NewFile = New-Item -ItemType File -Name $CSV_Name
$Remediation_details | select * | export-csv $CSV_Full_Path -notype -Delimiter ","  

$StorageAccount = Get-AzStorageAccount -Name $StorageAccount -ResourceGroupName $ResourceGroup
Set-AzStorageBlobContent -File $CSV_Full_Path -Container $Container -Blob $CSV_Name -Context $StorageAccount.Context -Force -ErrorAction Stop