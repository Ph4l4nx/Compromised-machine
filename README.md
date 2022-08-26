# Windows Compromised-machine

* List all SW that starts automatically when the system boots: wmic startup list full

* List all USB connected to the host: Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*

* List all the executed commands in the system: Get-History 

* All SW installed: reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName" //// Get-CimInstance -ClassName Win32_Product

* FW: netsh advfirewall show global

* List all recently opened documents: openfiles /query (take a time)

* List of all open named pipes in Windows: get-childitem \\.\pipe\ or [System.IO.Directory]::EnumerateFiles('\\.\pipe\')

* View cached DNS entries: ipconfig /displaydns

* Get all connections: Get-NetTCPConnection

* View currently executing processes: Get-Process // to investigate further: Get-Process chrome | Select-Object Id, ProcessName, Path, Company, StartTime | Format-Table

* To obtain the execution-policy: Get-ExecutionPolicy 

* To list all the users: Get-LocalUser

* Getting all the GP0'S: Get-GPO –all

* Get-PSReadLineOption 

* In order to search magic numbers (4D 5A) in non-executable file extensions: Get-Content .\file –Encoding Byte | Format-Hex

* To detect shellcodes, we need to search for the following hex values: "8B EC".

* http://sandsprite.com/blogs/index.php?uid=7&pid=152 in order to search shellcodes in .dll or .exe files. Example: https://blog.nviso.eu/2022/04/06/analyzing-a-multilayer-maldoc-a-beginners-guide/

* Base64 (1024chars) content in a file: Get-Content .\file | Select-String '[A-Za-z0-9\/\+]{1024,}[=]{0,2}'

* https://github.com/last-byte/PersistenceSniper

* Autoruns and process hacker cambiandoles el nombre

* Para identificar de donde se ha descargado un fichero: more < file:Zone.Identifier


# Linux Compromised-Machine

* watch -n 0 ss -tpn
* htop | top
* pstree
* ps aux
* lastlog
* lsof -i | sudo lsof
* netstat -putona
* netstat -ab | findstr :3389
* sudo iptables -L
* Interesting files: proxychains, cron, passwd, resolv.conf, bashrc

Cheatsheet: https://www.security-hive.com/post/linux-forensics-the-complete-cheatsheet
