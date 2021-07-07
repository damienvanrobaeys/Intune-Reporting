$CompName = $env:computername
$Drivers_Test = Get-WmiObject Win32_PNPEntity | Where-Object {$_.ConfigManagerErrorCode -gt 0 }    
$Search_Disabled_Missing_Drivers = ($Drivers_Test | Where-Object {(($_.ConfigManagerErrorCode -eq 22) -or ($_.ConfigManagerErrorCode -eq 28))})
    
If(($Search_Disabled_Missing_Drivers).count -gt 0)	
	{		
		ForEach($Driver in $Search_Disabled_Missing_Drivers)
			{
				$Driver_Name = $Driver.Caption
				$Driver_DeviceID = $Driver.DeviceID
							
				If($Driver_Name -eq $null){$DRV_Name = "Empty"}Else{$DRV_Name = $Driver_Name}
				If($Driver.ConfigManagerErrorCode -eq 28)
					{
						$Error_type = "Missing"
					}
				ElseIf($Driver.ConfigManagerErrorCode -eq 22)
					{
						$Error_type = "Disabled"				
					}						
				$Device_Drivers_Issues +=  "$CompName;$Error_type;$DRV_Name;$Driver_DeviceID-"													
			}
			$Device_Drivers_Issues_Report = $Device_Drivers_Issues.TrimEnd('-')	
			write-output $Device_Drivers_Issues_Report
		EXIT 1
	}
Else
	{
		EXIT 0
	}

