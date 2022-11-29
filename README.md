# Windows Compromised-machine

  * [Table of Contents](#table-of-contents)                                                                                                                                                                                               
      * [Platforms to practice](#platforms-to-practice)
 ## Platforms to practice

* List all SW that starts automatically when the system boots: wmic startup list full 

* List all USB connected to the host: Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*

* List all the DISKS: Get-PhysicalDisk

* List all the process: Get-Process

* List all the scheduled tasks: Get-ScheduledTask

* List all the executed commands in the system: Get-History 

* All SW installed: reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName" //// Get-CimInstance -ClassName Win32_Product or wmic product get name,version

* FW: netsh advfirewall show global

* List all recently opened documents: openfiles /query (take a time)

* List of all open named pipes in Windows: get-childitem \\.\pipe\ or [System.IO.Directory]::EnumerateFiles('\\.\pipe\')

* View cached DNS entries: ipconfig /displaydns in Powershell: Get-DnsClientCache

* Get all connections: Get-NetTCPConnection && Get-NetUDPEndpoint

* View currently executing processes: Get-Process // to investigate further: Get-Process chrome | Select-Object Id, ProcessName, Path, Company, StartTime | Format-Table

* To obtain the execution-policy: Get-ExecutionPolicy 

* To list all the users: Get-LocalUser

* Getting all the GP0'S: Get-GPO –all

* Get-PSReadLineOption > type ..\PowerShell\PSReadLine\ConsoleHost_history.txt

* In order to search magic numbers (4D 5A) in non-executable file extensions: Get-Content .\file –Encoding Byte | Format-Hex

* To detect shellcodes, we need to search for the following hex values: "8B EC".

* http://sandsprite.com/blogs/index.php?uid=7&pid=152 in order to search shellcodes in .dll or .exe files. Example: https://blog.nviso.eu/2022/04/06/analyzing-a-multilayer-maldoc-a-beginners-guide/

* Base64 (1024chars) content in a file: Get-Content .\file | Select-String '[A-Za-z0-9\/\+]{1024,}[=]{0,2}'

* https://github.com/last-byte/PersistenceSniper

* Autoruns and process hacker cambiandoles el nombre

* Para identificar de donde se ha descargado un fichero: more < file:Zone.Identifier

* Live memory analysis: https://github.com/ignacioj/WhacAMole

------------------------------------------------------------------------------------------------------------------------

* Check with BeaconHunter: https://github.com/3lp4tr0n/BeaconHunter. Ex: BeaconHunter.exe winhttp.dll <process id> -mthp More info: https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/
  
* https://github.com/thefLink/Hunt-Sleeping-Beacons


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


