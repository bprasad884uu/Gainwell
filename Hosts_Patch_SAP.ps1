# Path to hosts file
$etcLoc = "C:\Windows\System32\drivers\etc"
$hostsPath = Join-Path $etcLoc "hosts"
$backupPath = Join-Path $etcLoc "hosts.bak"

# Take backup if not already backed up
if (-not (Test-Path $backupPath)) {
    Copy-Item -Path $hostsPath -Destination $backupPath -Force
    Write-Host "Backup created at: $backupPath"
} else {
    Write-Host "Backup already exists at: $backupPath"
}

# New content for hosts file
$newHostsContent = @"
# Copyright (c) 1993-1999 Microsoft Corp.
#
# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.
#
# This file contains the mappings of IP addresses to host names. Each
# entry should be kept on an individual line. The IP address should
# be placed in the first column followed by the corresponding host name.
# The IP address and the host name should be separated by at least one
# space.
#
# Additionally, comments (such as these) may be inserted on individual
# lines or following the machine name denoted by a '#' symbol.
#
# For example:
#
#      102.54.94.97     rhino.acme.com          # source server
#       38.25.63.10     x.acme.com              # x client host

127.0.0.1       	localhost
##AMT
10.131.17.36	AMT-APP
10.131.17.37	AMT-DB
10.131.17.38	GCPL-AZ-AMTTST
##PI Production Systems
10.131.51.167 px1tiplscs px1tiplscs.tiplindia.com
##ERP Production Systems
10.131.51.216    pe1tipldb       pe1tipldb.tiplindia.com
10.131.51.203    pe1tiplscs      pe1tiplscs.tiplindia.com
10.131.51.221    pe1tiplap1      pe1tiplap1.tiplindia.com
10.131.51.240    pe1tiplap2      pe1tiplap2.tiplindia.com
## CRM Production Servers
10.131.51.246    pc1tiplap1  pc1tiplap1.tiplindia.com
10.131.51.237    pc1tipldb   pc1tipldb.tiplindia.com
10.131.51.205    pc1tiplscs  pc1tiplscs.tiplindia.com
10.131.51.242    pc1tiplap2  pc1tiplap2.tiplindia.com
## EP Production
10.131.51.248    pp1tipldb pp1tipldb.tiplindia.com
10.131.51.227    pp1tiplscs pp1tiplscs.tiplindia.com
## All Quality Systems 
10.131.51.229    qcatipl	qcatipl.tiplindia.com
10.131.51.229    qe1tipl	qe1tipl.tiplindia.com
10.131.51.204 	piqa piqa.tiplindia.com
10.131.51.140	tiplcrm.tiplindia.com
##S`/4 Hana
172.25.4.102	vhgazps4ci.sap.gainwellindia.com
"@

# Replace hosts file
Set-Content -Path $hostsPath -Value $newHostsContent -Force -Encoding ASCII

Write-Host "Hosts file has been replaced successfully."
