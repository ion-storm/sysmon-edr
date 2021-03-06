# Sysmon EDR v1 by ion-storm
# Instructions:
# Set your Sysmmon rules to Comma Seperated Key Value Pairs
# To Kill processes add kp=y your sysmon rules
# To Shutdown System add sd=y
# To Null route ip add nr=y
# To Firewall off ip add fw=y
# You can add Multiples ^
# Send desktop notifications to all users
$Notify = "TRUE"
# Force Null route if route exists
$Force = "TRUE"
$cports = "C:\programdata\edr\cports.exe"
$notification = "A Suspicious event was detected on your system, notify the SOC Team immediately!"
Register-WmiEvent -Query "Select * From __InstanceCreationEvent Where TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.LogFile='Microsoft-Windows-Sysmon/Operational' AND TargetInstance.Message Like '%Alert%'" -SourceIdentifier "Sysmon"
Try{
	While ($True) {
		$NewEvent = Wait-Event -SourceIdentifier Sysmon
		$Log = $NewEvent.SourceEventArgs.NewEvent.TargetInstance
		$LogName  = $Log.LogFile
		$SourceName   = $Log.SourceName
        $Category = $Log.CategoryString
		$EventID  = $Log.EventCode
		$Time = $Log.TimeGenerated
		$Year =  $Time.SubString(0, 4)
		$Month = $Time.SubString(4, 2)
		$Day =  $Time.SubString(6, 2)
		$Hour = $Time.SubString(8, 2)
		$Minutes =  $Time.SubString(10, 2)
		$Date = $Year + "/" + $Month + "/" + $Day + " " + $Hour + ":" + $Minutes
		$Date = (([DateTime]$Date)).AddHours(9).ToString("yyyy/MM/dd HH:mm:ss")
		$Message = $Log.Message
        #Process Create Event Detection
		if($EventID -eq 1)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
            #Debug $Message uncomment to remove
            foreach($i in $msg){Write-Host $i}
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			# Sysmon Event ID 1 Vars
			$UtcTime = $sysmon."UtcTime"
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$FileVersion = $sysmon."FileVersion"
			$Description = $sysmon."Description"
			$Product = $sysmon."Product"
			$Company = $sysmon."Company"
			$OriginalFileName = $sysmon."OriginalFileName"
			$CommandLine = $sysmon."CommandLine"
			$CurrentDirectory = $sysmon."CurrentDirectory"
			$User = $sysmon."User"
			$LogonGuid = $sysmon."LogonGuid"
			$LogonId = $sysmon."LogonId"
			$TerminalSessionId = $sysmon."TerminalSessionId"
			$Hashes = $sysmon."Hashes"
			$Hashes2 = $Hashes -split ','
			$Hashtable = $Hashes2 | ConvertFrom-StringData
			$MD5 = $Hashtable."MD5"
			$SHA256 = $Hashtable."SHA256"
			$IMPHASH = $Hashtable."IMPHASH"
			$ParentProcessId = $sysmon."ParentProcessId"
			$ParentImage = $sysmon."ParentImage"
			$ParentCommandLine = $sysmon."ParentCommandLine"
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert User: $User Executed $CommandLine within $CurrentDirectory from $ParentImage at $UtcTime"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " User: $User Executed $CommandLine within $CurrentDirectory from $ParentImage at $UtcTime" + "`n" + "$notification"
                    $message | msg *
                }
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /PID $ProcessId
					}
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
					}
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
					}
				}
            else {
            }
        }
        #Network Connect Event Detection
		if($EventID -eq 3)
        {
            #Debug $Message uncomment to remove
            foreach($i in $msg){Write-Host $i}
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			# Sysmon Event ID 3 
			$UtcTime = $sysmon."UtcTime"
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$User = $sysmon."User"
			$Protocol = $sysmon."Protocol"
			$Initiated = $sysmon."Initiated"
			$SourceIsIpv6 = $sysmon."SourceIsIpv6"
			$SourceIp = $sysmon."SourceIp"
			$SourceHostname = $sysmon."SourceHostname"
			$SourcePort = $sysmon."SourcePort"
			$SourcePortName = $sysmon."SourcePortName"
			$DestinationIsIpv6 = $sysmon."DestinationIsIpv6"
			$DestinationIp = $sysmon."DestinationIp"
			$DestinationHostname = $sysmon."DestinationHostname"
			$DestinationPort = $sysmon."DestinationPort"
			$DestinationPortName = $sysmon."DestinationPortName"
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" +"User: $User Initiated network connection with $Image to IP: $DestinationIp Host: $DestinationHostname" + "`n" +"$notification"
                    $message | msg *
                }
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /PID $ProcessId
					}
				if($msg[1].ToLower().Contains("kc=y")){
					Write-Host "[+] Killing connection to: $DestinationIp"
					start-process -FilePath $cports -ArgumentList "/close * * * * $ProcessId"
					}
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
					}
				if($msg[1].ToLower().Contains("nr=y")){
					# This is currently untested, code used from https://gallery.technet.microsoft.com/Add-and-Remove-Null-Routes-cfc77032
					Write-Host "[+] Null routing IP..."
					$msgdapters = (Get-NetAdapter | ? { $_.MediaConnectionState -eq "Connected" -and $_.InterfaceDescription -notlike "*Xbox*" }).InterfaceIndex
					foreach ($msgdapter in $msgdapters) {
						foreach ($msgddress in $IPAddress) 
						{
							Write-Host "Specified Address is $($msgddress)"
							if ($msgddress -notlike "*/*") { $msgddress = $msgddress + "/32" }
							Write-Host "Null routing address $($msgddress)"
							$IfAddressExists = [bool](Get-NetRoute -DestinationPrefix $msgddress -ea SilentlyContinue)
							switch ($IfAddressExists)
							{	
								true {
									if (!$Force) { Write-Host "Route already exists.  Use -Force parameter to update existing route." }
									If ($Force)
									{
										Write-Host "Updating destination $($msgddress)."
										Set-NetRoute -InterfaceIndex $msgdapter -DestinationPrefix $msgddress -NextHop 0.0.0.0
									}
								}
								false { 
									Write-Host "Processing $($msgddress) for adapter $($msgdapter)."
									New-NetRoute -InterfaceIndex $msgdapter -DestinationPrefix $msgddress -NextHop 0.0.0.0
								}
							}
						}
					}
				}
            }
            else {
            }
        }
        Remove-Event Sysmon
	}
Catch{
	Write-Warning "Error"
	Write-Output "$Date" $Error[0]| Out-file "C:\ProgramData\edr\errorlog.txt" -append
    $Error[0] }
}Finally{
    Get-Event | Remove-Event 
    Get-EventSubscriber | Unregister-Event 
	}
