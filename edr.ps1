<#  
   _____                                     __________  ____ 
  / ___/__  ___________ ___  ____  ____     / ____/ __ \/ __ \
  \__ \/ / / / ___/ __ `__ \/ __ \/ __ \   / __/ / / / / /_/ /
 ___/ / /_/ (__  ) / / / / / /_/ / / / /  / /___/ /_/ / _, _/ 
/____/\__, /____/_/ /_/ /_/\____/_/ /_/  /_____/_____/_/ |_|  
     /____/ v1 by ionstorm
	Features:
	MITRE ATT&CK Rule Tagging
	Kill Parent Processes and all Child Processes
	Kill network connections of processes
	Shut down System
	Firewall off Processes
	Desktop Notifications
	Yara Scanning
	
	Instructions:
	Set your Sysmon rules to Comma Seperated Key Value Pairs
	Ensure that Registry file is imported to allow WMI event Subscription to the windows event log
	
	Your sysmon Rulename must contain Alert with the following response tags:
	kp=y 	Kill process with child processes
	kpp=y 	Kill Parent Processes & all Child Processes
	kc=y    Kill network connections
	ki=y    Kill Injected Thread
	sd=y 	Shutdown System
	fw=y	Add Windows Firewall Rule to block inbound/outbound network connectivity from process
	yara=y  Yara Scan file
	ydel=y  Delete on Yara Detection
	rf=y    Restore Deleted File
	nr=y 	Null route ip (Unfinished)
	
	You can add Multiple tags for multiple Live responses
	Send desktop notifications to all users
	
	Future Feature ideas:
	Automatic restore of files from ransomware events with mounting & restore of shadow copies or integration with veeam to restore files.
	Uninjection of injected processes
	Network Isolation
	Eventlog Logging of detections, responses and errors.
	Yara scanning of detections
	Archiving of files detected as malicious with password protected archive
	Implement modified invoke-dropnet instead of cports with process name/path killing of connections.
	
	To Do:
	Move Actions to Function Module
	Threading
#>
<# Option Variables #>
$Notify = "TRUE"
# Force Null route if route exists
$Force = "TRUE"
$cports = "C:\programdata\edr\cports.exe"
$yararules = "C:\programdata\edr\yararules\china_chopper.yar"
$notification = "A Suspicious event was detected on your system, notify the SOC Team immediately!"
ipmo C:\programdata\edr\stop-thread.ps1
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
		#
        #Process Create Event Detection and Response
		if($EventID -eq 1)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			#
            #Debug $Message uncomment to remove
            #foreach($i in $msg){Write-Host $i}
			#
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
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
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert User: $User Executed $CommandLine within $CurrentDirectory from $ParentImage at $UtcTime"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " User: $User Executed $CommandLine within $CurrentDirectory from $ParentImage at $UtcTime" + "`n" + "$notification"
                    $message | msg *
                }
				# Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Parent Process Killer
				if($msg[1].ToLower().Contains("kpp=y")){
					Write-Host "[+] Killing: $ParentProcessId"
					taskkill /F /T /PID $ParentProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Firewall Process
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = C:\programdata\edr\yara64.exe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
			}
            else {
            }
        }
        #Network Connect Event Detection and Response
		if($EventID -eq 3)
        {
            #Debug $Message uncomment to remove
            #foreach($i in $msg){Write-Host $i}
			#
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			#
			# Key/Value Tags from Sysmon RuleName
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
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
			#
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
                Write-Host "[+] Alert: $Alert"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" +"User: $User Initiated network connection with $Image to IP: $DestinationIp Host: $DestinationHostname" + "`n" +"$notification"
                    $message | msg *
                }
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Connection Killer
				if($msg[1].ToLower().Contains("kc=y")){
					Write-Host "[+] Killing connection to: $DestinationIp"
					start-process -FilePath $cports -ArgumentList "/close * * * * $ProcessId"
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = C:\programdata\edr\yara64.exe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
				<#
				# Null Route (Unfinished)
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
				#>
            }
            else {
            }
        }
        #Remote Thread Events
		if($EventID -eq 8)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			#
            #Debug $Message uncomment to remove
            foreach($i in $msg){Write-Host $i}
			#
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 8 Vars
			$UtcTime = $sysmon."UtcTime"
			$SourceProcessGuid = $sysmon."SourceProcessGuid"
			$SourceProcessId = $sysmon."SourceProcessId"
			$SourceImage = $sysmon."SourceImage"
			$TargetProcessGuid = $sysmon."TargetProcessGuid"
			$TargetProcessId = $sysmon."TargetProcessId"
			$TargetImage = $sysmon."TargetImage"
			$NewThreadId = $sysmon."NewThreadId"
			$StartModule = $sysmon."StartModule"
			$StartFunction = $sysmon."StartFunction"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $SourceImage Created Remote Thread within $TargetImage with Function $StartFunction from Thread ID: $NewThreadId at $UtcTime"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " $Alert Process: $SourceImage Created Remote Thread within $TargetImage with Function $StartFunction from Thread ID: $NewThreadId at $UtcTime" + "`n" + "$notification"
                    $message | msg *
                }
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				#Injected Thread Killer
				if($msg[1].ToLower().Contains("ki=y")){
					Write-Host "[+] Killing Remote Thread: $NewThreadId"
					Stop-Thread -ThreadId $NewThreadId
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = C:\programdata\edr\yara64.exe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
			}
            else {
            }
        }
        #File Create Event Detection and Response
		if($EventID -eq 11)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			#
            #Debug $Message uncomment to remove
            foreach($i in $msg){Write-Host $i}
			#
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 11 Vars
			$UtcTime = $sysmon."UtcTime"
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetFilename = $sysmon."TargetFilename"
			$CreationUtcTime = $sysmon."CreationUtcTime"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $Image Created $TargetFilename with Process ID: $ProcessId at $UtcTime"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " $Alert Process: $Image Created $TargetFilename with Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                    $message | msg *
                }
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Connection Killer
				if($msg[1].ToLower().Contains("kc=y")){
					Write-Host "[+] Killing connection to: $DestinationIp"
					start-process -FilePath $cports -ArgumentList "/close * * * * $ProcessId"
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $TargetFilename with Yara..."
					$result = C:\programdata\edr\yara64.exe -c $yararules "$TargetFilename"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $TargetFilename as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $targetFilename"
						Remove-Item -Path "$TargetFilename" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
			}
            else {
            }
        }
        #Registry Items
		if($EventID -eq 13)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			#
            #Debug $Message uncomment to remove
            foreach($i in $msg){Write-Host $i}
			#
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 13 Vars
			$UtcTime = $sysmon."UtcTime"
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$TargetObject = $sysmon."TargetObject"
			$EventType = $sysmon."EventType"
			$Details = $sysmon."Details"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $Image Created Registry Item $TargetObject with details: $Details from Process ID: $ProcessId at $UtcTime"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " $Alert Process: $Image Created $TargetFilename with Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                    $message | msg *
                }
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Connection Killer
				if($msg[1].ToLower().Contains("kc=y")){
					Write-Host "[+] Killing connection to: $DestinationIp"
					start-process -FilePath $cports -ArgumentList "/close * * * * $ProcessId"
				}
				# Shutdown System
				if($msg[1].ToLower().Contains("sd=y")){
					Write-Host "[+] shutting down system..."
					shutdown.exe -s -t 30 -c "This system is shutting down in 30 seconds, save your work immediately.."
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $TargetFilename with Yara..."
					$result = C:\programdata\edr\yara64.exe -c $yararules "$TargetFilename"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $TargetFilename as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $targetFilename"
						Remove-Item -Path "$TargetFilename" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
			}
            else {
            }
        }
        #DNS Events
		if($EventID -eq 22)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			#
            #Debug $Message uncomment to remove
            foreach($i in $msg){Write-Host $i}
			#
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 22 Vars
			$UtcTime = $sysmon."UtcTime"
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$Image = $sysmon."Image"
			$QueryName = $sysmon."QueryName"
			$QueryResults = $sysmon."QueryResults"
			$QueryStatus = $sysmon."QueryStatus"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $Image Initiated DNS Request to $QueryName with the results: $QueryResults from Process ID: $ProcessId at $UtcTime"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " $Alert Process: $Image Initiated DNS Request to $QueryName with the results: $QueryResults from ProcessID: $ProcessId at $UtcTime" + "`n" + "$notification"
                    $message | msg *
                }
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = C:\programdata\edr\yara64.exe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
			}
            else {
            }
        }
        #File Delete Events
		if($EventID -eq 23)
        {
            $msg = $Message -split "`r`n"
			$msg2 = $msg.replace(': ','=').replace('\','\\')
			$msg3 = $msg2 | Select -Skip 2
			$sysmon = $msg3 | ConvertFrom-StringData
			#
            #Debug $Message uncomment to remove
            foreach($i in $msg){Write-Host $i}
			#
			# Key/Value Tags from Sysmon RuleName
			$data = $msg[1] -split ','
			$data2 = $data |ConvertFrom-StringData
			$MitreRef = $data2."MitreRef"
			$Technique = $data2."Technique"
			$Tactic = $data2."Tactic"
			$Alert = $data2."Alert"
			#
			# Sysmon Event ID 22 Vars
			$UtcTime = $sysmon."UtcTime"
			$ProcessGuid = $sysmon."ProcessGuid"
			$ProcessId = $sysmon."ProcessId"
			$User = $sysmon."User"
			$Image = $sysmon."Image"
			$TargetFilename = $sysmon."TargetFilename"
			$Hashes = $sysmon."Hashes"
			$IsExecutable = $sysmon."IsExecutable"
			$Archived = $sysmon."Archived"
			#
			# Begin Actions
            if($msg[1].ToLower().Contains("alert=")) #Mitre Attack Desktop Alerts
            {
				# Desktop Alerts
                Write-Host "[+] Alert: $Alert Process: $Image Deleted File $TargetFilename from Process ID: $ProcessId at $UtcTime"
                if($Notify){
                    $message = "Alert: " + $Alert + "`n" + "Technique: " + $Technique + "`n" + "Tactic: " + $Tactic + "`n" + " $Alert Process: $Image Deleted File $TargetFilename from Process ID: $ProcessId at $UtcTime" + "`n" + "$notification"
                    $message | msg *
                }
				#Process Killer
				if($msg[1].ToLower().Contains("kp=y")){
					Write-Host "[+] Killing: $ProcessId"
					taskkill /F /T /PID $ProcessId
				}
				# Yara Scan
				if($msg[1].ToLower().Contains("yara=y")){
					Write-Host "[+] Scanning $Image with Yara..."
					$result = C:\programdata\edr\yara64.exe -c $yararules "$Image"
					if($result -gt "0"){ 
					Write-Host "[+] Yara detected file $Image as malicious or suspicious..."
					if($msg[1].ToLower().Contains("ydel=y")){
						Write-Host "[+] Deleting file $Image"
						Remove-Item -Path "$Image" -Force
					}
                    }
					else {
						Write-Host "[-] Yara detected file as clean.."
					}
				}
				# Firewall Blocking
				if($msg[1].ToLower().Contains("fw=y")){
					Write-Host "[+] Blocking process: $image from internet access..."
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image in" protocol=tcp dir=in enable=yes action=block profile=any program="$Image"
					netsh advfirewall firewall add rule name="Sysmon EDR Block $Image out" protocol=tcp dir=out enable=yes action=block profile=any program="$Image"
				}
				# File Restore
				if($msg[1].ToLower().Contains("rf=y")){
					$pattern = "(MD5=|\,SHA256=|\,IMPHASH=)"
					$File = $Hashes -replace $pattern
					$TargetFilename -match ".([A-Za-z0-9]+)$"
					$ext = $matches[0]
					$TargetFilename -match "^([a-z]):"
					$drv = $matches[0]
					Write-Host "[+] Restoring: $drv\DeletedFiles\$file$ext to Original Location: $TargetFilename..."
					Move-Item -Path "$drv\DeletedFiles\$File$ext" -Destination "$TargetFilename" -Force
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
