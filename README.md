  * [Table of Contents](#table-of-contents)                                                                                                                                                                         
      - [Windows](#windows)                     
        * [System Information](#system-information)
        * [Persistence](#persistence)
        * [Lateral Movement](#lateral-movement)
        * [Communications](#communications)
        * [Malware](#malware)
            * [Metadata](#metadata)
            * [SW](#sw)
            * [Lolbas](#lolbas)
        * [Hooking](#hooking)
        * [Triage](#triage)
        * [Analysis](#analysis)
        * [Blogs](#blogs)
      - [Linux](#linux)
        * [System Information](#system-information-1)
        * [Communications](#communications-1)
        * [Persistence](#persistence-1)
        * [Triage](#triage-1)
        * [Others](#others)
        * [Logs](#logs)
        * [Blogs](#blogs-1)
      - [Android](#android)
        * [Triage](#triage-2)
         
# Windows

 ## System Information
 
* View currently executing processes: Get-Process // to investigate further: Get-Process chrome | Select-Object Id, ProcessName, Path, Company, StartTime | Format-Table

* List all the executed commands in the system: Get-History 

* Get the last 100 events from the application log: Get-EventLog -LogName Application -Newest 100

* Get the security log events generated in the last 24 hours:Get-EventLog -LogName Security -After (Get-Date).AddDays(-1)

* Get the error level events in the system log: Get-EventLog -LogName System -EntryType Error

* All SW installed: reg query HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall /s | findstr "DisplayName" //// Get-CimInstance -ClassName Win32_Product or wmic product get name,version
 
* List all USB connected to the host: 1) Get-ItemProperty -ea 0 hklm:\system\currentcontrolset\enum\usbstor\*\* | select FriendlyName,PSChildName 
2) Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*
 
* List all the Disks: Get-PhysicalDisk

* To obtain the execution-policy: Get-ExecutionPolicy 

* To list all the users: Get-LocalUser

* Getting all the GP0'S: Get-GPO –all

* Live memory analysis: https://github.com/ignacioj/WhacAMole

* Get-PSReadLineOption > type ..\PowerShell\PSReadLine\ConsoleHost_history.txt

* FW configuration: netsh advfirewall show global

* List all recently opened documents: openfiles /query (take a time)

* From cmd: net user & net user 'username'
 
* From cmd: lusrmgr -> Local users and groups

 ## Persistence
 
* List all SW that starts automatically when the system boots: wmic startup list full

* List all the scheduled tasks: Get-ScheduledTask

* PersistenceSniper: https://github.com/last-byte/PersistenceSniper

* Hunt Sleeping Beacons: https://github.com/thefLink/Hunt-Sleeping-Beacons

 ## Lateral Movement

* List of all open named pipes in Windows (SMB): get-childitem \\.\pipe\ or [System.IO.Directory]::EnumerateFiles('\\.\pipe\') or [System.IO.Directory]::GetFiles("\\.\pipe")

*  Sysinternal tool: https://learn.microsoft.com/en-us/sysinternals/downloads/handle E.g: handle.exe chrome

* Lateral movement analyzer: https://github.com/silverfort-open-source/latma && https://www.kitploit.com/2023/01/latma-lateral-movement-analyzer-tool.html?m=1

## Communications

* View cached DNS entries: ipconfig /displaydns in Powershell: Get-DnsClientCache

* Get all connections: Get-NetTCPConnection && Get-NetUDPEndpoint

* netstat -ab | findstr :3389

* Get-VpnConnection

## Malware

* In order to search magic numbers (4D 5A) in non-executable file extensions: Get-Content .\file –Encoding Byte | Format-Hex

* http://sandsprite.com/blogs/index.php?uid=7&pid=152 in order to search shellcodes in .dll or .exe files. Example: https://blog.nviso.eu/2022/04/06/analyzing-a-multilayer-maldoc-a-beginners-guide/

* Base64 (1024chars) content in a file: Get-Content .\file | Select-String '[A-Za-z0-9\/\+]{1024,}[=]{0,2}'

* Check with BeaconHunter: https://github.com/3lp4tr0n/BeaconHunter. Ex: BeaconHunter.exe winhttp.dll <process id> -mthp More info: https://www.mdsec.co.uk/2022/08/part-3-how-i-met-your-beacon-brute-ratel/

### Metadata

* dir /r in order to get ADS from files
* File download source: more < file:Zone.Identifier -> Zone.Identifier is an ADS attribute.

### SW

* Autoruns and process hacker changing their names

* Process Explorer -> Options -> Check Virustotal.com

* Sysinspector: https://support.eset.com/es/que-es-eset-sysinspector

* Ram-capturer: https://belkasoft.com/ram-capturer

* Pe-sieve: https://github.com/hasherezade/pe-sieve/releases
 
### Lolbins:
 
* Important lolbas to be aware: Wmic.exe, Mshta.exe, Certutil.exe, Hh.exe, Cscript.exe, Regini.exe, Cmd.exe, Rundll32.exe, Schtasks.exe and Shell32.dll
 
* Reference: https://lolbas-project.github.io/

## Hooking
 
* tasklist /m EasyHook32.dll;tasklist /m EasyHook64.dll;tasklist /m EasyLoad32.dll;tasklist /m EasyLoad64.dll;
 
 ## Triage

* Fast triage: Process Explorer -> Options -> Check Virustotal.com

* Malware in memory: https://github.com/JPCERTCC/YAMA
 
* RAM: DumpIt (https://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html) & https://github.com/Velocidex/WinPmem
 
 FTK imager
 
* WinTriage: https://www.securizame.com/wintriage-la-herramienta-de-triage-para-el-dfirer-en-windows/
 
* KAPE: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape#form716
 
 ## Analysis
 
* Autopsy: https://www.autopsy.com/download/
 
 Volatility

 ## Blogs
 
* Process Explorer Sysinternals: https://nasbench.medium.com/hunting-malware-with-windows-sysinternals-process-explorer-2baec974bec9
* https://www.jaiminton.com/cheatsheet/DFIR/#
 
# Linux

## System Information
 
* ps aux
* lastlog
* htop | top
* pstree & ps -auxwf
* lsof
* sudo iptables -L
* dpkg -l 
* Monitor linux processes: https://github.com/DominicBreuker/pspy
* Auditd
* Sysdig
 
## Communications
 
* watch -n 0 ss -tpn
* lsof -i  
* netstat -putona
 
 ## Persistence
 
 systemctl ->  By service
 
 cat ~/.bashrc & ~/.zshrc -> By configuration file/action
 
 crontab -l -> Take care of the user context -> By scheduled task
 
 ## Triage
 
 * FastIR: https://github.com/SekoiaLab/Fastir_Collector_Linux
 
 * LIME: https://fwhibbit.es/volcado-de-memoria-ram-en-linux-lime
 
 * Remote triage. Pylirt: https://github.com/anil-yelken/pylirt

 ## Others
 
* Interesting files: /etc/proxychains, /etc/crontab, /etc/passwd, /etc/sudoers, /etc/shadow, /etc/resolv.conf, /etc/network/interfaces &  ~/.ssh/config
 
* readelf file.elf or file.so -h
 
* readelf file.elf or file.so -n
 
* cat /proc/pid/maps
 
* objdump -s -j .rodata file.so
 
* objdump file.so

* strace -f .elf file

* strace -f -o strace_out.txt .elf file

## Logs
 
 * dmesg -> kernel information logs

/var/log/syslog, /var/log/auth.log, /var/log/kern.log, /var/log/dmesg & /var/log/messages.

## Blogs

* https://pberba.github.io/security/

# Android

## Triage

* PcapDroid: https://play.google.com/store/apps/details?id=com.emanuelef.remote_capture&hl=es_419&gl=US 

