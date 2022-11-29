  * [Table of Contents](#table-of-contents)                                                                                                                                                                         
      - [Windows](#windows)                     
        * [System Information](#system-information)
        * [Persistence](#persistence)
        * [Lateral Movement](#lateral-movement)
        * [Communications](#communications)
        * [Malware in the system](#malware-in-the-system)
        * [Metadata](#metadata)
      - [Linux](#linux)

# Windows

 ## System Information
 
* View currently executing processes: Get-Process // to investigate further: Get-Process chrome | Select-Object Id, ProcessName, Path, Company, StartTime | Format-Table

* List all the executed commands in the system: Get-History 

* All SW installed: reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName" //// Get-CimInstance -ClassName Win32_Product or wmic product get name,version
 
* List all USB connected to the host: Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*
 
* List all the Disks: Get-PhysicalDisk

* To obtain the execution-policy: Get-ExecutionPolicy 

* To list all the users: Get-LocalUser

* Getting all the GP0'S: Get-GPO –all

* Live memory analysis: https://github.com/ignacioj/WhacAMole

* Get-PSReadLineOption > type ..\PowerShell\PSReadLine\ConsoleHost_history.txt

* FW configuration: netsh advfirewall show global

* List all recently opened documents: openfiles /query (take a time)

 ## Persistence
 
* List all SW that starts automatically when the system boots: wmic startup list full

* List all the scheduled tasks: Get-ScheduledTask

* Autoruns and process hacker changing their names

* PersistenceSniper: https://github.com/last-byte/PersistenceSniper

 ## Lateral Movement

* List of all open named pipes in Windows (SMB): get-childitem \\.\pipe\ or [System.IO.Directory]::EnumerateFiles('\\.\pipe\')

## Communications

* View cached DNS entries: ipconfig /displaydns in Powershell: Get-DnsClientCache

* Get all connections: Get-NetTCPConnection && Get-NetUDPEndpoint

## Malware in the system

* Hunt sleeping Beacons: https://github.com/thefLink/Hunt-Sleeping-Beacons

* In order to search magic numbers (4D 5A) in non-executable file extensions: Get-Content .\file –Encoding Byte | Format-Hex

* To detect shellcodes, we need to search for the following hex values: "8B EC".

* http://sandsprite.com/blogs/index.php?uid=7&pid=152 in order to search shellcodes in .dll or .exe files. Example: https://blog.nviso.eu/2022/04/06/analyzing-a-multilayer-maldoc-a-beginners-guide/

* Base64 (1024chars) content in a file: Get-Content .\file | Select-String '[A-Za-z0-9\/\+]{1024,}[=]{0,2}'

* Check with BeaconHunter: https://github.com/3lp4tr0n/BeaconHunter. Ex: BeaconHunter.exe winhttp.dll <process id> -mthp More info: https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/

## Metadata

* dir /r in order to get ADS from files
* File download source: more < file:Zone.Identifier -> Zone.Identifier is an ADS attribute.


# Linux

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


