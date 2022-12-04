  * [Table of Contents](#table-of-contents)                                                                                                                                                                         
      - [Windows](#windows)                     
        * [System Information](#system-information)
        * [Persistence](#persistence)
        * [Lateral Movement](#lateral-movement)
        * [Communications](#communications)
        * [Malware](#malware)
            * [Online engines](#online-engines)     
            * [Distros to analyze malware](#distros-to-analyze-malware)
            * [Tools](#tools)
            * [Free AVs and sandboxes](#free-avs-and-sandboxes)
            * [Ransomware](#ransomware)
            * [APTs](#apts)
            * [Blogs and Information](#blogs-and-information)
            * [Metadata](#metadata)
            * [SW](#sw)
            * [Lolbas](#lolbas)
      - [Linux](#linux)
        * [System Information](#system-information-1)
        * [Communications](#communications-1)
        * [Others](#others)

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

* PersistenceSniper: https://github.com/last-byte/PersistenceSniper

 ## Lateral Movement

* List of all open named pipes in Windows (SMB): get-childitem \\.\pipe\ or [System.IO.Directory]::EnumerateFiles('\\.\pipe\')

## Communications

* View cached DNS entries: ipconfig /displaydns in Powershell: Get-DnsClientCache

* Get all connections: Get-NetTCPConnection && Get-NetUDPEndpoint

* netstat -ab | findstr :3389

## Malware

* In order to search magic numbers (4D 5A) in non-executable file extensions: Get-Content .\file –Encoding Byte | Format-Hex

* http://sandsprite.com/blogs/index.php?uid=7&pid=152 in order to search shellcodes in .dll or .exe files. Example: https://blog.nviso.eu/2022/04/06/analyzing-a-multilayer-maldoc-a-beginners-guide/

* Base64 (1024chars) content in a file: Get-Content .\file | Select-String '[A-Za-z0-9\/\+]{1024,}[=]{0,2}'

* Check with BeaconHunter: https://github.com/3lp4tr0n/BeaconHunter. Ex: BeaconHunter.exe winhttp.dll <process id> -mthp More info: https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/

### Online engines

* Virustotal: https://www.virustotal.com/gui/home/search

* Online Cuckoo Sandbox: https://sandbox.pikker.ee/

* Polyswarm: https://polyswarm.network

* Joesandbox: https://www.joesandbox.com/#windows

* Intezer: https://analyze.intezer.com/scan

* Hybrid Analysis: https://www.hybrid-analysis.com/?lang=es

* Database of counterfeit-related webs: https://desenmascara.me/

* ANY.RUN https://any.run/

https://antiscan.me/

https://www.virscan.org/

https://metadefender.opswat.com/?lang=en

### Distros to analyze malware

* Linux Distro to investigate malware: https://docs.remnux.org/

* Windows Distro to investigate malware: https://github.com/mandiant/flare-vm

### Tools

* Sysinternals: https://docs.microsoft.com/en-us/sysinternals/

* Sysinspector: https://support.eset.com/es/que-es-eset-sysinspector

* Autoruns: https://docs.microsoft.com/en-us/sysinternals/downloads/autoruns

* RAM capturer: https://belkasoft.com/ram-capturer

* Recopilation: https://github.com/rshipp/awesome-malware-analysis

* Reverse Engineer's Toolkit: https://github.com/mentebinaria/retoolkit

* PEstudio: https://www.winitor.com/

* Malzilla: https://malzilla.org/

* PROCMON+PCAP: https://www.procdot.com/

* Analyze APK's: https://github.com/quark-engine/quark-engine && https://github.com/mvt-project/mvt && https://github.com/pjlantz/droidbox

* Hunt Sleeping Beacons: https://github.com/thefLink/Hunt-Sleeping-Beacons

* Persistence Sniper: https://github.com/last-byte/PersistenceSniper

* XORSearch: https://blog.didierstevens.com/programs/xorsearch/

* RAT Decoder: https://github.com/kevthehermit/RATDecoders

* Malwoverview: https://github.com/alexandreborges/malwoverview

* Binary strings defuser: https://github.com/fireeye/flare-floss

* Network analysis of malware (emulate HTTP server): https://github.com/felixweyne/imaginaryC2

* This tool allows you to intercept and redirect all or specific network traffic while simulating legitimate network services: https://github.com/mandiant/flare-fakenet-ng

### Free AVs and Sandboxes

* ClamAV: https://www.clamav.net/downloads#otherversions

* MAC AV: https://www.pcrisk.es/mejores-programas-antivirus/8365-combo-cleaner-antivirus-and-system-optimizer-mac

* Sandbox: https://github.com/CERT-Polska/drakvuf-sandbox

* DragonFly: https://dragonfly.certego.net/register

* Offline Sandbox: https://sandboxie-plus.com/downloads/

### Ransomware

* Ransomware decryption tools: http://files-download.avg.com/util/avgrem/avg_decryptor_Legion.exe, https://success.trendmicro.com/solution/1114221-downloading-and-using-the-trend-micro-ransomware-file-decryptor, https://www.nomoreransom.org/es/decryption-tools.htmlm, https://www.avast.com/es-es/ransomware-decryption-tools , https://noransom.kaspersky.com/ , https://www.mcafee.com/enterprise/es-es/downloads/free-tools/ransomware-decryption.html, https://www.mcafee.com/enterprise/en-us/downloads/free-tools.html, https://www.emsisoft.com/ransomware-decryption-tools/. 

* General Overview: https://docs.google.com/spreadsheets/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml#

* Ransomware groups: http://edteebo2w2bvwewbjb5wgwxksuwqutbg3lk34ln7jpf3obhy4cvkbuqd.onion/

### APTs

* Intelligence: https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml# && https://github.com/StrangerealIntel/EternalLiberty/blob/main/EternalLiberty.csv && https://xorl.wordpress.com/

Are you an APT target? -> https://lab52.io/

* APT Simulator: https://github.com/NextronSystems/APTSimulator

### Blogs and Information

* Macros: https://blog.didierstevens.com/2021/01/19/video-maldoc-analysis-with-cyberchef/ && https://blog.nviso.eu/2022/04/06/analyzing-a-multilayer-maldoc-a-beginners-guide/

* Malware examples/binaries: https://bazaar.abuse.ch/, https://github.com/ytisf/theZoo & https://malshare.com/

## Metadata

* dir /r in order to get ADS from files
* File download source: more < file:Zone.Identifier -> Zone.Identifier is an ADS attribute.

## SW

* Autoruns and process hacker changing their names

* Sysinspector: https://support.eset.com/es/que-es-eset-sysinspector

* Ram-capturer: https://belkasoft.com/ram-capturer
 
 ## Lolbas
 
 Important lolbas to be aware: Wmic.exe, Mshta.exe, Certutil.exe, Hh.exe, Cscript.exe, Regini.exe, Cmd.exe, Rundll32.exe, Schtasks.exe and Shell32.dll
 
 Reference: https://lolbas-project.github.io/

# Linux

## System Information
 
* ps aux
* lastlog
* htop | top
* pstree 
* lsof
* sudo iptables -L
* Monitor linux processes: https://github.com/DominicBreuker/pspy
 
## Communications
 
* watch -n 0 ss -tpn
* lsof -i  
* netstat -putona

 ## Others
 
* Interesting files: proxychains, cron, passwd, resolv.conf, bashrc


