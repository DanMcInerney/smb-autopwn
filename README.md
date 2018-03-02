# smb-autopwn
Discovers and exploits hosts vulnerable to MS08-067

Runs Nmap with the NSE scripts for detecting ms08-067 and ms17-010 then opens metasploit in an xterm window which will not close when the script ends. Metasploit is ran with an automatically generated rc file that will automatically exploit the vulnerable host then perform the following:

* Migrate to a new process
* Kill the firewall
* Dump NTLM hashes
* Gather WDigest credentials
* Run credential harvester
* Enable RDP

*** Usage
```./smb-autpwn.py -l targetips.txt```
