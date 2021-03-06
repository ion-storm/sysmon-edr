$trigger = New-ScheduledTaskTrigger -AtStartup 
$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-ExecutionPolicy Bypass -File C:\ProgramData\edr\edr.ps1'
$settingsSet = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 999 -ExecutionTimeLimit (New-TimeSpan -Seconds 0) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$User = "NT AUTHORITY\SYSTEM"
$task = New-ScheduledTask -Trigger $trigger -Action $action -Settings $settingsSet
Register-ScheduledTask -TaskName 'Sysmon_EDR' -InputObject $task -Force -User $User
