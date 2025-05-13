@echo off

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_GCPL_SAP_VPN" /v "Description" /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "Server" /t REG_SZ /d "13.200.0.109:10443" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "DATA1" /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "promptusername" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "promptcertificate" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "DATA3" /t REG_SZ /d "" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "ServerCert" /t REG_SZ /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "dual_stack" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "sso_enabled" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "use_external_browser" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels\AWS_SSL_GCPL" /v "azure_auto_login" /t REG_DWORD /d 00000000 /f

echo Registry keys have been added.