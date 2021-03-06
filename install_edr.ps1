$scpath = 'C:\windows\system32\sc.exe'
$scarg = 'CREATE sysmon_edr Displayname= "sysmon_edr" binpath= "\"C:\Programdata\edr\start_edr.bat\"" start= auto'
$scstart = 'start sysmon_edr'
$regpath = 'C:\Programdata\edr\enable_sysmon_wmi.reg'
$service = Get-Service -Name sysmon_edr -ErrorAction SilentlyContinue
$installdir = 'C:\Programdata\edr\'
If (!(Test-Path -Path 'C:\Programdata\edr')){
	mkdir "$installdir"
	copy-item "$PSScriptRoot\edr.ps1" "$installdir" -Force -EA SilentlyContinue
	copy-item "$PSScriptRoot\enable_sysmon_wmi.reg" "$installdir" -Force -EA SilentlyContinue
	copy-item "$PSScriptRoot\start_edr.bat" "$installdir" -Force -EA SilentlyContinue
	}
	If (!($service.Length -gt 0)){
		regedit.exe /s $regpath
		Start-Process -FilePath $scpath -ArgumentList $scarg -Wait -WindowStyle Hidden
		Start-Process -FilePath $scpath -ArgumentList $scstart -WindowStyle Hidden
	}
