# Compromised-machine

* List all SW that starts automatically when the system boots: wmic startup list full

* List all USB connected to the host: Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*

* List of all open named pipes in Windows: get-childitem \\.\pipe\

* FW: netsh advfirewall show global
