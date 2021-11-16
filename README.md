# Compromised-machine

* List all SW that starts automatically when the system boots: wmic startup list full

* List all USB connected to the host: Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*

* All SW installed: reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName"

* FW: netsh advfirewall show global

* List all recently opened documents: openfiles /query (take a time)

* List of all open named pipes in Windows: get-childitem \\.\pipe\

