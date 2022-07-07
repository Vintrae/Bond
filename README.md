# Bond
An automated IP analysis tool using public APIs.

Bond allows the user the automate the scan of IP addresses instead of having to manually analyse them one service at a time. To do so, it uses publicly
available API endpoints for multiple services to perform the analysis. Currently, the following services are supported:
- VirusTotal
- ipinfo.io
- vpnapi.io
- AbuseIPDB

## Requirements

In order to run Bond you need to have API keys to every supported service. This can be done by setting them as environment variables. Currently, the following
environment variables must be present for the program to run:
```
VT_API_KEY
IPINFO_API_KEY
VPNAPI_API_KEY
ABUSEIPDB_API_KEY
```
In Windows environments, these can be set using the ```setx``` command:
```
setx VT_API_KEY your_key_here
```
In Linux/Mac OS environments, these can be set temporarily using the ```export``` command:
```
export VT_API_KEY=your_key_here
```
or permanently by placing the command in the ```~/.bash_profile.sh``` or ```~/.bash-profile``` files repectively.

## Usage
Using Bond is pretty simple: just paste your IP addresses in the left box and click on the 'Import' button. Alternatively, click on 'Browse' to search for a
text file containing a list of IP addresses. Bond is expecting an IP address per line in both cases, and supports defanged IP addresses. It will also
automatically strip any ```"``` or ```,``` characters.


Once the analysis is done, the various service tabs will be enabled. Clicking on them will show the results for each of them. Only one field per IP address is initially
visible, but all the data can be seen by clicking on the expand button. Finally, all data can be exported in an Excel file by clicking on the 'Export' button, which will
save each tab in a different sheet.
