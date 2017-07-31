#requires -module TervisApplication,RemoteDesktop,TervisJava

function Invoke-RemoteWebBrowserAppProvision {
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName RemoteWebBrowserApp -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName RemoteWebBrowserApp -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_StoresRDS_RemoteDesktop'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Stores Remote Desktop Services'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Update-StoreManagerToStoresRdsPrivilege
}

function Invoke-StoresRemoteDesktopProvision {
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName StoresRemoteDesktop -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName StoresRemoteDesktop -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_StoresRDS_RemoteDesktop'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Stores Remote Desktop Services'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Update-StoreManagerToStoresRdsPrivilege
}

function Invoke-KeyscanRemoteAppProvision {
    [CmdletBinding()]
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName KeyscanRemoteApp -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName KeyscanRemoteApp -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_KeyscanRemoteApp'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Keyscan RemoteApp'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Set-KeyscanOptions -DatabaseLocation Keyscan
}

function Invoke-WCSRemoteAppProvision {
    [CmdletBinding()]
    param (
        $EnvironmentName
    )
    Invoke-ApplicationProvision -ApplicationName WCSRemoteApp -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName WCSRemoteApp -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_WCSRemoteApp'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'WCS RemoteApp'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Set-JavaHomeEnvironmentVariable
    $Nodes | Install-WCSJavaRemoteAppClient
}

function Invoke-DataLoadClassicRemoteAppProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName DataLoadClassic -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName DataLoadClassic -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_DataLoadClassicRemoteApp'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'DataLoad Classic RemoteApp'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Set-JavaToolOptionsEnvironmentVariable
    $Nodes | Install-TervisJava7DeploymentRuleSet
    $Nodes | Disable-JavaUpdate
}

function Invoke-WindowsAppsRemoteAppProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName WindowsApps -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName WindowsApps -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_WindowsAppsRemoteApp'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Windows Applications RemoteApp'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
}

function Invoke-TervisEBSRemoteAppProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName EBSRemoteApp -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName EBSRemoteApp -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_TervisEBSRemoteApp'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Tervis EBS RemoteApp'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Set-JavaToolOptionsEnvironmentVariable
    $Nodes | Install-TervisJava7DeploymentRuleSet
    $Nodes | Disable-JavaUpdate
    $Nodes | Set-TervisEBSRemoteAppBrowserPreferences
    $Nodes | Set-TervisEPSConfiguration

}

function Invoke-RemoteDesktopGatewayProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName RemoteDesktopGateway -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName RemoteDesktopGateway -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRDGatewayServer
    $Nodes | Set-TervisRDGatewayAuthorizationPolicy
    $Nodes | Add-TervisRdsAppLockerLink
    Set-TervisRDCertificate -Role RDGateway
}

function Invoke-RemoteDesktopWebAccessProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName RemoteDesktopWebAccess -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName RemoteDesktopWebAccess -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRDWebAccessServer
    $Nodes | Add-TervisRdsAppLockerLink
    Set-TervisRDCertificate -Role RDWebAccess
}

function Get-TervisRDBroker {
    Get-ADComputer -filter 'Name -like "*broker*"' | 
        Select -ExpandProperty DNSHostName
}

function Add-TervisRdsServer {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    Begin {
        $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    Process {
        $SessionHost = $ComputerName + '.' + $DNSRoot
        If (-NOT (Get-RDServer -ConnectionBroker $RDBroker -Role RDS-RD-SERVER -ErrorAction SilentlyContinue | Where Server -Contains $SessionHost)) {
            Add-RDServer -Server $SessionHost -ConnectionBroker $RDBroker -Role RDS-RD-SERVER
        }
    }
}

function New-TervisRdsSessionCollection {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ApplicationName,
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName,
        [Parameter(Mandatory)]$CollectionSecurityGroup,
        [Parameter(Mandatory)]$CollectionDescription
    )
    Begin {
        $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    Process {
        $CollectionName = "$(Get-TervisEnvironmentPrefix -EnvironmentName $EnvironmentName) $ApplicationName"
        If (-NOT (Get-RDSessionCollection -ConnectionBroker $RDBroker -CollectionName $CollectionName -ErrorAction SilentlyContinue)) {
            $SessionHost = $ComputerName + '.' + $DNSRoot
            New-RDSessionCollection -CollectionName $CollectionName -ConnectionBroker $RDBroker -SessionHost $SessionHost -CollectionDescription $CollectionDescription
            Set-RDSessionCollectionConfiguration `
                -ConnectionBroker $RDBroker `
                -CollectionName $CollectionName `
                -UserGroup $CollectionSecurityGroup `
                -DisconnectedSessionLimitMin 720 `
                -IdleSessionLimitMin 720 `
                -AutomaticReconnectionEnabled $true
        }
    }
}

function Add-TervisRDGatewayServer {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    process {
        $RDGatewayFQDN = $ComputerName + '.' + $DNSRoot
        if (-not (Get-RDServer -ConnectionBroker $RDBroker -Role RDS-GATEWAY -ErrorAction SilentlyContinue | where Server -Contains $RDGatewayFQDN)) {
            Add-RDServer -Server $RDGatewayFQDN -Role RDS-GATEWAY -ConnectionBroker $RDBroker
        }
    }
}

function Add-TervisRDWebAccessServer {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    process {
        $RDWebAccessFQDN = $ComputerName + '.' + $DNSRoot
        if (-not (Get-RDServer -ConnectionBroker $RDBroker -Role RDS-WEB-ACCESS -ErrorAction SilentlyContinue | where Server -Contains $RDWebAccessFQDN)) {
            Add-RDServer -Server $RDWebAccessFQDN -Role RDS-WEB-ACCESS -ConnectionBroker $RDBroker
        }
    }
}

function Update-Privilege_StoresRDS_RemoteDesktop {
    param()
    $StoreManagers = Get-PaylocityEmployees -Status A | where {$_.DepartmentName -eq 'Stores' -and $_.JobTitle -eq 'Store Manager'}
    $StoreManagerAdUsers = @()
    foreach ($Manager in $StoreManagers) {
        $EmployeeID = ($Manager).EmployeeID
        $StoreManagerAdUsers += Get-ADUser -Filter {EmployeeID -eq $EmployeeID} -Properties MemberOf,EmployeeID
    }
    Foreach ($Employee in $StoreManagerAdUsers) {
        If (-NOT (($Employee).MemberOf -like "*Privilege_StoresRDS_RemoteDesktop*")) {
            Add-ADGroupMember -Identity 'Privilege_StoresRDS_RemoteDesktop' -Members ($Employee).DistinguishedName
        }
    }
    $GroupMembers = Get-ADGroupMember -Identity 'Privilege_StoresRDS_RemoteDesktop'
    $SearchBase = ($GroupMembers | Where DistinguishedName -like "*OU=Store Accounts,*")[0].DistinguishedName.Split(",",2)[1]
    $StoreAccounts = Get-ADUser -Filter {(Enabled -eq $true)} -SearchBase $SearchBase | Where {$_.Name -NotMatch "POS" -and $_.Name -notmatch "2"}
    Foreach ($StoreAccount in $StoreAccounts) {
        If (-NOT (($StoreAccount).MemberOf -like "*Privilege_StoresRDS_RemoteDesktop*")) {
            Add-ADGroupMember -Identity 'Privilege_StoresRDS_RemoteDesktop' -Members ($StoreAccount).DistinguishedName
        }
    }
    If ($StoreManagerAdUsers -and $GroupMembers) {
        foreach ($GroupMember in $GroupMembers) {
            If (-NOT (($GroupMember).DistinguishedName -like "*OU=Store Accounts,*" -or ($GroupMember).DistinguishedName -in ($StoreManagerAdUsers).DistinguishedName)) {
                Remove-ADGroupMember -Identity 'Privilege_StoresRDS_RemoteDesktop' -Members ($GroupMember).DistinguishedName -Confirm:$false
            }
        }
    } else {
        Throw "The StoreManagerAdUser variable is empty."
    }
}

function Install-StoresRDSRemoteDesktopPrivilegeScheduledTasks {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $ScheduledTaskCredential = New-Object System.Management.Automation.PSCredential (Get-PasswordstateCredential -PasswordID 259)
        $Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $Argument = '-Command Update-StoreManagerToStoresRdsPrivilege -NoProfile'
    }
    process {
        $CimSession = New-CimSession -ComputerName $ComputerName
        If (-NOT (Get-ScheduledTask -TaskName Update-Privilege_StoresRDS_RemoteDesktop -CimSession $CimSession -ErrorAction SilentlyContinue)) {
            Install-TervisScheduledTask -Credential $ScheduledTaskCredential -TaskName Update-Privilege_StoresRDS_RemoteDesktop -Execute $Execute -Argument $Argument -RepetitionIntervalName EveryDayAt2am -ComputerName $ComputerName
        }
    }
}

function Add-TervisRdsSessionHost {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ApplicationName,
        [Parameter(ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    Begin {
        $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    Process {
        $CollectionName = "$(Get-TervisEnvironmentPrefix -EnvironmentName $EnvironmentName) $ApplicationName"
        $SessionHost = $ComputerName + '.' + $DNSRoot
        If (-NOT ((Get-RDSessionHost -CollectionName $CollectionName -ConnectionBroker $RDBroker -ErrorAction SilentlyContinue).SessionHost -contains $SessionHost)) {            
            Add-RDSessionHost -CollectionName $CollectionName -SessionHost $SessionHost -ConnectionBroker $RDBroker
        }
    }
}

function New-BackOfficeRDPFileContent {
    param (
        $UserName
    )
@"
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,3,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:2
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:INF-StoresRDS01
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:RDGATEWAY2012R2
gatewayusagemethod:i:2
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
redirectdirectx:i:1
username:s:$UserName
"@
}

function New-BackOfficeManagerRDPFileContent {

@"
screen mode id:i:2
use multimon:i:0
desktopwidth:i:1920
desktopheight:i:1080
session bpp:i:32
winposstr:s:0,3,0,0,800,600
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:2
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:INF-StoresRDS01
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:1
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:RDGATEWAY2012R2
gatewayusagemethod:i:2
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
redirectdirectx:i:1
"@

}

function New-BackOfficeRemoteDesktopRDPFile {
    param (
        [Parameter(Mandatory)]$ComputerName,
        [Parameter(ParameterSetName="UserName")]$UserName,
        [Parameter(ParameterSetName="ManagerRDPFile")][Switch]$ManagerRDPFile
    )
    begin {
        $PublicDesktopPath = "c:\users\public\Desktop"
    }
    process {
        $RemoteDesktopRDPContent = if ($UserName) { 
            New-BackOfficeRDPFileContent -UserName $UserName
        } else {
            New-BackOfficeManagerRDPFileContent
        }
        $PublicDesktopPathRemote = $PublicDesktopPath | ConvertTo-RemotePath -ComputerName $ComputerName
        $RDPFileName = if ($UserName) {
            "$PublicDesktopPathRemote/Remote Desktop.rdp"
        } else {
            "$PublicDesktopPathRemote/Manager Remote Desktop.rdp"
        }
        $RemoteDesktopRDPContent | Out-File -FilePath $RDPFileName -NoNewline -Encoding ascii -Force
    }
}

function Remove-BackOfficeRemoteDesktopRDPFile {
    param (
        $ComputerName,
        $UserName
    )
    begin {
        $PublicDesktopPath = "c:\users\public\Desktop"
    }
    process {
        $PublicDesktopPathRemote = $PublicDesktopPath | ConvertTo-RemotePath -ComputerName $ComputerName
        Remove-Item -Path "$PublicDesktopPathRemote/Remote Desktop.rdp"
    }
}

function Add-TervisRdsAppLockerLink {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ApplicationName
    )
    Begin {
        $AppLockerGPO = Get-TervisApplockerGPO -GpoTarget RdsServer
        $GPOTrustee = Get-GPPermission -All -Name ($AppLockerGPO).DisplayName | `
            Where {$_.Permission -match 'GpoApply'} | `
            Select -ExpandProperty Trustee | `
            Select -ExpandProperty Name
    }
    Process {
        if (-not ((Get-ADGroupMember $GPOTrustee).name -contains $ComputerName)) {
            $ComputerObject = Get-ADComputer $ComputerName | Select -ExpandProperty DistinguishedName
            Add-ADGroupMember -Identity $GPOTrustee -Members $ComputerObject
        }
        $TargetOU = Get-TervisApplicationOrganizationalUnit -ApplicationName $ApplicationName | Select -ExpandProperty DistinguishedName
        New-GPLink -Guid ($AppLockerGPO).Id -Target $TargetOU -ErrorAction SilentlyContinue
    }
}

function Set-KeyscanOptions {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(Mandatory)]$DatabaseLocation,
        [String]$RegionalTimeZone = "Eastern Standard Time"
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-Item -Path "HKLM:\Software\VB and VBA Program Settings"
            New-Item -Path "HKLM:\Software\VB and VBA Program Settings\KEYSCAN7"
            New-Item -Path "HKLM:\Software\VB and VBA Program Settings\KEYSCAN7\DatabaseLocation"
            New-Item -Path "HKLM:\Software\VB and VBA Program Settings\KEYSCAN7\RegionalTimeZone"
            New-ItemProperty -Path "HKLM:\Software\VB and VBA Program Settings\KEYSCAN7\DatabaseLocation" -Name Address -Value $Using:DatabaseLocation -PropertyType String
            New-ItemProperty -Path "HKLM:\Software\VB and VBA Program Settings\KEYSCAN7\RegionalTimeZone" -Name StandardName -Value $Using:RegionalTimeZone -PropertyType String
        } | Out-Null
    }
}

function Set-TervisRDGatewayAuthorizationPolicy {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $ADDomain = (Get-ADDomain).Name       
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Import-Module -Name RemoteDesktopServices
            New-Item -Name Tervis_CAP -Path RDS:\GatewayServer\CAP -UserGroups "Privilege_RDGatewayAccess@$Using:ADDomain" -AuthMethod 1
            New-Item -Name Tervis_RAP -Path RDS:\GatewayServer\RAP -UserGroups "Privilege_RDGatewayAccess@$Using:ADDomain" -ComputerGroupType 1 -ComputerGroup "Domain Computers@$Using:ADDomain"
        }
    }
}

function Set-TervisRDCertificate {
    param (
        [ValidateSet("RDWebAccess","RDGateway","RDPublishing","RDRedirector")]
        [Parameter(Mandatory)]$Role
    )
    $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
    $CertificatePath = "$env:TEMP\certificate.pfx"
    $CertificateCredential = (Get-PasswordstateCredential -PasswordID 2570)
    Get-PasswordstateDocument -DocumentID 3 -FilePath $CertificatePath
    Set-RDCertificate -Role $Role -ImportPath $CertificatePath -Password $CertificateCredential.Password -ConnectionBroker $RDBroker -Force
    Remove-Item -Path $CertificatePath -Force
}

function Set-TervisRDBrokerSettings {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    $BrokerURI = Invoke-WmiMethod -Class "Win32_RDMSDeploymentSettings" -Namespace "root\CIMV2\rdms" -Name "GetStringProperty" `
            -ArgumentList @("DeploymentRedirectorServer") -ComputerName $ComputerName `
            -Authentication PacketPrivacy -ErrorAction Stop | fl
    if (-NOT ($BrokerURI -like "*.tervis.com")) {
    $NewBrokerURI = ($ComputerName + 'tervis.com').ToUpper()
    Invoke-WmiMethod -Class "Win32_RDMSDeploymentSettings" -Namespace "root\CIMV2\rdms" -Name "SetStringProperty" `
            -ArgumentList @("DeploymentRedirectorServer",$NewBrokerURI) -ComputerName $ComputerName `
            -Authentication PacketPrivacy -ErrorAction Stop
    }
}

function Install-TervisRemoteAppsOnWindows7 {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]
        [Alias("Name")]$ComputerName
    )
    begin {
        $DomainName = Get-ADDomain | select -ExpandProperty DNSRoot
        $StartUpDirectory = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
        $InstallCommandFile = @"
powershell -windowstyle hidden -noprofile -Command "\\$DomainName\applications\Powershell\TervisRemoteApp\Install-TervisRemoteApp.ps1"
"@
    }    
    process {
        $StartUpDirectoryRemote = $StartUpDirectory | ConvertTo-RemotePath -ComputerName $ComputerName
        $InstallCommandFile | Out-File -FilePath $StartUpDirectoryRemote\TervisRemoteApp.cmd -Encoding ascii -Force
    }
}

function Set-TervisEBSRemoteAppBrowserPreferences {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $DomainName = Get-ADDomain | select -ExpandProperty DNSRoot
    }
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-Item -Path "C:\Program Files (x86)\Mozilla Firefox\browser" -Name "defaults" -ItemType Directory
            New-Item -Path "C:\Program Files (x86)\Mozilla Firefox\browser\defaults" -Name "preferences" -ItemType Directory
            Copy-Item -Path \\$Using:DomainName\applications\PowerShell\FirefoxPreferences\autoconfig.js -Destination "C:\Program Files (x86)\Mozilla Firefox\browser\defaults\preferences\"
            Copy-Item -Path \\$Using:DomainName\applications\PowerShell\FirefoxPreferences\mozilla.cfg -Destination "C:\Program Files (x86)\Mozilla Firefox\"
            Copy-Item -Path \\$Using:DomainName\applications\PowerShell\FirefoxPreferences\override.ini -Destination "C:\Program Files (x86)\Mozilla Firefox\browser"
        }
    }    
}

function Write-RemoteAppDefinition {
    param (
        [Parameter(Mandatory)]$RemoteApps
    )
    $RemoteAppDefinitionString = [System.Text.StringBuilder]::new()
    $RemoteAppCollections = $RemoteApps | select -Unique CollectionName
    foreach ($Collection in $RemoteAppCollections.CollectionName) {
        $RemoteAppDefinitionString.Append(@"
[PSCustomObject][Ordered]@{
    Name = "$($Collection.Substring(4))"
    CollectionName = "$Collection"
    RemoteAppDefinition = ,
"@) | Out-Null
        $RemoteAppsInCollection = $RemoteApps | where CollectionName -eq $Collection
        foreach ($RemoteApp in $RemoteAppsInCollection) {
            $RemoteAppDefinitionString.AppendLine(@"
@{
        Alias = "$($RemoteApp.Alias)"
        DisplayName = "$($RemoteApp.DisplayName)"
        FilePath = "$($RemoteApp.FilePath)"
        ShowInWebAccess = [bool]`$$($RemoteApp.ShowInWebAccess)
        CommandLineSetting = "$($RemoteApp.CommandLineSetting)"
        RequiredCommandLine = "$($RemoteApp.RequiredCommandLine)"
        UserGroups = "$($RemoteApp.UserGroups)"
    },
"@) | Out-Null
        }
        $RemoteAppDefinitionString.Length = $RemoteAppDefinitionString.Length - 3
        $RemoteAppDefinitionString.AppendLine() | Out-Null
        $RemoteAppDefinitionString.AppendLine("},") | Out-Null
    }
    $RemoteAppDefinitionString.Length = $RemoteAppDefinitionString.Length - 3
    $DomainReplace = (Get-ADDomain).DNSRoot
    $RemoteAppDefinitionString.Replace($DomainReplace,'$((Get-ADDomain).DNSRoot)') | Out-Null
    $RemoteAppDefinitionString.ToString()
}
