# Compromised-machine

* List all SW that starts automatically when the system boots: wmic startup list full

* List all USB connected to the host: Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*

* All SW installed: reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName"

* FW: netsh advfirewall show global

* List all recently opened documents: openfiles /query (take a time)

* List of all open named pipes in Windows: get-childitem \\.\pipe\

* View cached DNS entries: ipconfig /displaydns

* Get all connections: Get-NetTCPConnection

* View currently executing processes: Get-Process // to investigate further: Get-Process chrome | Select-Object Id, ProcessName, Path, Company, StartTime | Format-Table

* To obtain the execution-policy: Get-ExecutionPolicy 

* To list all the users: Get-LocalUser



