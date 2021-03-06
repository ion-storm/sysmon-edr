## sysmon-edr

# Sysmon EDR Active Response Features
* Mitre ATT&CK Desktop Alerts
* Yara Scanning
* Malicious Process Killing
* Killing of Malicious process connections
* Blocking of Process network connectivity with Windows Firewall
* Response with Yara Detections


# Planned Future features:
* Host isolation with null routes
* Host Isolation with system shut down
* Host isolation with exceptions for support sites/AV/EDR rule to allow outlook/common apps only.
* Automated process memory dumping for forensics
* Automated threat removal based on signatures and behavior: Process Kill then Quarantine or Delete file, Service stop and quarantine or delete file, Kill process and remove registry persistence, startup folder file removal.
* Automated upload of malicious files and memory dumps
* Automated Registry/Scheduled Task/Service and Persistence removal
* Detection of Injected processes and uninject them
* VSS Snapshot restoration of files by mounting restore point, copying uninfected files to original location: Could utilize Sysmon's new restore abilities
* Undo changes made by malware(if it gets that far)
* Collect incident response data when suspicious activity is detected, upload to repository.
	* Autoruns, Installed Programs, Network Connections, Prefetch files, running processes, security logs, suspicious folder location items, newly created users and groups and more.
* Quarantine malicious files instead of delete by moving to a Quarantine directory.
