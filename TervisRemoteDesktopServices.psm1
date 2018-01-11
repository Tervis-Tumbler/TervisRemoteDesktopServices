#requires -module TervisApplication,RemoteDesktop,TervisJava

$RemoteAppDefinition = [PSCustomObject][Ordered]@{
    Name = "RemoteApps"
    CollectionName = "INF EBSRemoteApp"
    RemoteAppDefinition = ,@{
        Alias = "firefox"
        DisplayName = "DEVRP - EBS Rapid Planning [Delta]"
        FilePath = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://dlt-ias01.$((Get-ADDomain).DNSRoot):8006/OA_HTML/AppsLogin -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "firefox (1)"
        DisplayName = "PRDRP - EBS Rapid Planning [Production]"
        FilePath = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://ebsapps-prd.$((Get-ADDomain).DNSRoot):8011/OA_HTML/AppsLogin -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "firefox (2)"
        DisplayName = "SITRP - EBS Rapid Planning [Epsilon]"
        FilePath = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://eps-ias01.$((Get-ADDomain).DNSRoot):8006/OA_HTML/AppsLogin -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "iexplore"
        DisplayName = "PRD - E-Business Suite (EBS) [Production]"
        FilePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://ebsapps-prd.$((Get-ADDomain).DNSRoot):8010 -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "iexplore (1)"
        DisplayName = "SIT - E-Business Suite (EBS) [Epsilon]"
        FilePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://eps-ias01.$((Get-ADDomain).DNSRoot):8005/OA_HTML/AppsLogin -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "iexplore (2)"
        DisplayName = "DEV - E-Business Suite (EBS) [Delta]"
        FilePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://dlt-ias01.$((Get-ADDomain).DNSRoot):8005/OA_HTML/AppsLogin -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "iexplore (4)"
        DisplayName = "CNV - E-Business Suite (EBS) [Zeta]"
        FilePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://zet-ias01.$((Get-ADDomain).DNSRoot):8005/ -noframemerging"
        UserGroups = ""
    }
},
[PSCustomObject][Ordered]@{
    Name = "WCSRemoteApp"
    CollectionName = "INF WCSRemoteApp"
    RemoteAppDefinition = ,@{
        Alias = "DLTWCS"
        DisplayName = "DLT - WCS App "
        FilePath = "c:\DLT-WCS.cmd"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "DoNotAllow"
        RequiredCommandLine = ""
        UserGroups = ""
    },
@{
        Alias = "EPSWCS"
        DisplayName = "EPS - WCS App "
        FilePath = "c:\EPS-WCS.cmd"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "DoNotAllow"
        RequiredCommandLine = ""
        UserGroups = ""
    },
@{
        Alias = "PRDWCS"
        DisplayName = "PRD - WCS App"
        FilePath = "c:\PRD-WCS.cmd"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "DoNotAllow"
        RequiredCommandLine = ""
        UserGroups = ""
    }
},
[PSCustomObject][Ordered]@{
    Name = "WindowsApps"
    CollectionName = "INF WindowsApps"
    RemoteAppDefinition = ,@{
        Alias = "chrome"
        DisplayName = "Google Chrome"
        FilePath = "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "DoNotAllow"
        RequiredCommandLine = ""
        UserGroups = ""
    },
@{
        Alias = "explorer"
        DisplayName = "File Explorer"
        FilePath = "c:\Windows\explorer.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "DoNotAllow"
        RequiredCommandLine = ""
        UserGroups = ""
    },
@{
        Alias = "firefox"
        DisplayName = "Mozilla Firefox"
        FilePath = "C:\Program Files\Mozilla Firefox\firefox.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "DoNotAllow"
        RequiredCommandLine = ""
        UserGroups = ""
    },
@{
        Alias = "iexplore"
        DisplayName = "Internet Explorer"
        FilePath = "c:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "https://sharepoint.tervis.com/Pages/HomePage.aspx -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "MSACCESS"
        DisplayName = "Helix Downtime Client"
        FilePath = "C:\Program Files (x86)\Microsoft Office\Office16\MSACCESS.EXE"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "'\\$((Get-ADDomain).DNSRoot)\departments\Departments - I Drive\Shared\Operations\Chad\Helix\Helix Downtime Client.accdb'"
        UserGroups = "TERVIS\Privilege_Helix_RemoteApps"
    }
},
[PSCustomObject][Ordered]@{
    Name = "SilverlightIE"
    CollectionName = "INF SilverlightIE"
    RemoteAppDefinition = ,@{
        Alias = "iexplore"
        DisplayName = "Edgenet Supplier Portal"
        FilePath = "c:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://supplier.edgenet.com"
        UserGroups = ""
    }
},
[PSCustomObject][Ordered]@{
    Name = "FedExShipManager"
    CollectionName = "INF FedExShipManager"
    RemoteAppDefinition = ,@{
        Alias = "fsm"
        DisplayName = "FedEx Ship Manager"
        FilePath = "C:\Program Files (x86)\FedEx\ShipManager\BIN\FedEx.Gsm.Cafe.ApplicationEngine.Gui.exe"
        ShowInWebAccess = [bool]$False
        CommandLineSetting = "DoNotAllow"
        RequiredCommandLine = ""
        UserGroups = ""
    }
},
[PSCustomObject][Ordered]@{
    Name = "EBSBusinessIntelligenceRemoteApp"
    CollectionName = "INF EBSBusinessIntelligenceRemoteApp"
    RemoteAppDefinition = ,@{
        Alias = "firefox"
        DisplayName = "PRD - EBS Business Intelligence (BI) [Production]"
        FilePath = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://ebsapps-prd.$((Get-ADDomain).DNSRoot):8010 -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "firefox (1)"
        DisplayName = "SIT - EBS Business Intelligence (BI) [Epsilon]"
        FilePath = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://eps-ias01.$((Get-ADDomain).DNSRoot):8005/OA_HTML/AppsLogin -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "firefox (2)"
        DisplayName = "DEV - EBS Business Intelligence (BI) [Delta]"
        FilePath = "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://dlt-ias01.$((Get-ADDomain).DNSRoot):8005/OA_HTML/AppsLogin -noframemerging"
        UserGroups = ""
    }
},
[PSCustomObject][Ordered]@{
    Name = "EBSDiscovererRemoteApp"
    CollectionName = "INF EBSDiscovererRemoteApp"
    RemoteAppDefinition = ,@{
        Alias = "iexplore"
        DisplayName = "PRD - Discoverer Plus [Production]"
        FilePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://discoverer.production.$((Get-ADDomain).DNSRoot):18090/discoverer/plus?eul=EUL_US&database=PRD&connectionAccessType=APPS&responsibility=Tervis%20Discoverer%20Reports -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "iexplore (1)"
        DisplayName = "SIT - Discoverer Plus [Epsilon]"
        FilePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://discoverer.epsilon.$((Get-ADDomain).DNSRoot):18090/discoverer/plus?eul=EUL_US&database=PRD&connectionAccessType=APPS&responsibility=Tervis%20Discoverer%20Reports -noframemerging"
        UserGroups = ""
    },
@{
        Alias = "iexplore (2)"
        DisplayName = "DEV - Discoverer Plus [Delta]"
        FilePath = "C:\Program Files\Internet Explorer\iexplore.exe"
        ShowInWebAccess = [bool]$True
        CommandLineSetting = "Require"
        RequiredCommandLine = "http://discoverer.delta.$((Get-ADDomain).DNSRoot):18091/discoverer/plus?eul=EUL_US&database=PRD&connectionAccessType=APPS&responsibility=Tervis%20Discoverer%20Reports -noframemerging"
        UserGroups = ""
    }
}



function Get-TervisRemoteAppDefinition {
    param (
        [Parameter(Mandatory)]$CollectionName
    )
    
    $RemoteAppDefinition | 
    where CollectionName -EQ $CollectionName
}

function Invoke-RemoteAppNodeProvision {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ApplicationName,
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$EnvironmentName
    )
    $RDBroker = Get-TervisRDBroker
    $CollectionName = "$(Get-TervisEnvironmentPrefix -EnvironmentName $EnvironmentName) $ApplicationName"
    $NodeRemoteAppDefinitions = Get-TervisRemoteAppDefinition -CollectionName $CollectionName
    foreach ($NodeRemoteAppDefinition in $NodeRemoteAppDefinitions) {
        foreach ($RemoteApp in $NodeRemoteAppDefinition.RemoteAppDefinition) {
            $RemoteAppParameters = $RemoteApp | Remove-HashtableKeysWithEmptyOrNullValues
            if (Get-RDRemoteApp -CollectionName $CollectionName -ConnectionBroker $RDBroker -DisplayName $RemoteApp.DisplayName) {
                Set-RDRemoteApp -CollectionName $CollectionName -ConnectionBroker $RDBroker @RemoteAppParameters
            } else {
                New-RDRemoteApp -CollectionName $CollectionName -ConnectionBroker $RDBroker @RemoteAppParameters
            }
        }
    }  
}

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
    $Nodes | Invoke-RemoteAppNodeProvision
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
    $Nodes | Set-JavaHomeEnvironmentVariable
    $Nodes | Set-JavaToolOptionsEnvironmentVariable
    $Nodes | Install-TervisJavaDeploymentRuleSet
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
    $Nodes | Invoke-RemoteAppNodeProvision
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
    $Nodes | Set-JavaHomeEnvironmentVariable
    $Nodes | Install-TervisJavaDeploymentRuleSet
    $Nodes | Disable-JavaUpdate
    $Nodes | Set-TervisEBSRemoteAppBrowserPreferences
    $Nodes | Set-TervisEPSConfiguration
    $Nodes | Invoke-RemoteAppNodeProvision
    $Nodes | Invoke-EBSWebADIServer2016CompatibilityHack
    $Nodes | Set-TervisEBSRemoteAppFileAssociations
}

function Invoke-TervisEBSBusinessIntelligenceRemoteAppProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName EBSBusinessIntelligenceRemoteApp -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName EBSBusinessIntelligenceRemoteApp -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_TervisEBSRemoteApp'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Tervis EBS Business Intelligence RemoteApp'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Set-JavaToolOptionsEnvironmentVariable
    $Nodes | Set-JavaHomeEnvironmentVariable
    $Nodes | Install-TervisJavaDeploymentRuleSet
    $Nodes | Disable-JavaUpdate
    $Nodes | Set-TervisEBSRemoteAppBrowserPreferences
    $Nodes | Invoke-RemoteAppNodeProvision
}

function Invoke-TervisEBSDiscovererRemoteAppProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName EBSDiscovererRemoteApp -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName EBSDiscovererRemoteApp -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_TervisEBSRemoteApp'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Tervis EBS Discoverer RemoteApp'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Set-JavaToolOptionsEnvironmentVariable
    $Nodes | Set-JavaHomeEnvironmentVariable
    $Nodes | Install-TervisJavaDeploymentRuleSet
    $Nodes | Disable-JavaUpdate
    $Nodes | Invoke-RemoteAppNodeProvision
}

function Invoke-SilverlightIERemoteAppProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName SilverlightIE -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName SilverlightIE -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_RemoteApp_SilverlightIE'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Silverlight IE for Edgenet'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Invoke-RemoteAppNodeProvision
}

function Invoke-TervisFedExShipManagerRemoteAppProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName FedExShipManager -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName FedExShipManager -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_RemoteApp_FedExShipManager'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'FedEx Ship Manager RemoteApp/Server'
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | Add-TervisRdsAppLockerLink
    $Nodes | Invoke-RemoteAppNodeProvision
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

function Invoke-RemoteDesktopLicensingProvision {
    param (
        $EnvironmentName = "Infrastructure"
    )
    Invoke-ApplicationProvision -ApplicationName RemoteDesktopLicensing -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisApplicationNode -ApplicationName RemoteDesktopLicensing -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRDLicensingServer
    $Nodes | Add-TervisRdsAppLockerLink
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
        $RDBroker = Get-TervisRDBroker
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    Process {
        $SessionHost = $ComputerName + '.' + $DNSRoot
        If (-NOT (Get-RDServer -ConnectionBroker $RDBroker -Role RDS-RD-SERVER -ErrorAction SilentlyContinue | Where Server -Contains $SessionHost)) {
            try {
                Add-RDServer -Server $SessionHost -ConnectionBroker $RDBroker -Role RDS-RD-SERVER -ErrorAction Stop
            } catch {
                Write-Verbose "$ComputerName`: Pending reboot. Restarting."
                Restart-Computer -ComputerName $ComputerName -Wait -Force
                Add-RDServer -Server $SessionHost -ConnectionBroker $RDBroker -Role RDS-RD-SERVER
            }
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
        $RDBroker = Get-TervisRDBroker
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
        $RDBroker = Get-TervisRDBroker
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
        $RDBroker = Get-TervisRDBroker
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    process {
        $RDWebAccessFQDN = $ComputerName + '.' + $DNSRoot
        if (-not (Get-RDServer -ConnectionBroker $RDBroker -Role RDS-WEB-ACCESS -ErrorAction SilentlyContinue | where Server -Contains $RDWebAccessFQDN)) {
            Add-RDServer -Server $RDWebAccessFQDN -Role RDS-WEB-ACCESS -ConnectionBroker $RDBroker
        }
    }
}

function Add-TervisRDLicensingServer {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $RDBroker = Get-TervisRDBroker
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    process {
        $RDLicensingFQDN = $ComputerName + '.' + $DNSRoot
        if (-not (Get-RDServer -ConnectionBroker $RDBroker -Role RDS-LICENSING -ErrorAction SilentlyContinue | where Server -Contains $RDLicensingFQDN)) {
            Add-RDServer -Server $RDLicensingFQDN -Role RDS-LICENSING -ConnectionBroker $RDBroker
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
        $RDBroker = Get-TervisRDBroker
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
    $RDBroker = Get-TervisRDBroker
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

function Invoke-EBSWebADIServer2016CompatibilityHack {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName,
        [Switch]$NoBackup
    )
    begin {
        $DomainAdminsNTAccount = [System.Security.Principal.NTAccount]::new($env:USERDOMAIN,"Domain Admins")
        $DomainAdminsFileSystemAccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new($DomainAdminsNTAccount,"FullControl","None","None","Allow")
        $AuthenticatedUsersFileSystemAccessRule = [System.Security.AccessControl.FileSystemAccessRule]::new("Authenticated Users","ReadAndExecute","None","None","Allow")
    }
    process {
        $HackedDllLocalItem = Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            $DateCode = Get-Date -Format FileDateTime
            $BackedUpDll = Rename-Item -Path C:\Windows\SysWOW64\msxml6.dll -NewName "msxml6.dll.$DateCode.bak" -PassThru         
            if ($using:NoBackup) {
                Remove-Item -Path $BackedUpDll.FullName
            }
            Copy-Item -Path C:\Windows\SysWOW64\msxml3.dll -Destination C:\Windows\SysWOW64\msxml6.dll -PassThru
        } -ErrorAction Stop
        
        $HackedDll = Get-Item -Path ($HackedDllLocalItem.FullName | ConvertTo-RemotePath -ComputerName $ComputerName)
        $HackedDllAcl = $HackedDll | Get-Acl
        $HackedDllAcl.SetOwner($DomainAdminsNTAccount)
        $HackedDllAcl.SetAccessRuleProtection($true,$false)
        $HackedDllAcl.AddAccessRule($DomainAdminsFileSystemAccessRule)
        $HackedDllAcl.AddAccessRule($AuthenticatedUsersFileSystemAccessRule)
        $HackedDllAcl | Set-Acl
    }
}

function Install-InvokeEBSWebADIServer2016CompatibilityHackScheduledTask {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $TaskName = "Invoke-EBSWebADIServer2016CompatibilityHack"
        $ScheduledTaskCredential = New-Object System.Management.Automation.PSCredential (Get-PasswordstateCredential -PasswordID 259)
        $Execute = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        $Argument = '-Command "& {Get-TervisApplicationNode -ApplicationName EBSRemoteApp -EnvironmentName Infrastructure | Invoke-EBSWebADIServer2016CompatibilityHack -NoBackup}"'
    }
    process {
        $CimSession = New-CimSession -ComputerName $ComputerName
        If (-NOT (Get-ScheduledTask -TaskName $TaskName -CimSession $CimSession -ErrorAction SilentlyContinue)) {
            Install-TervisScheduledTask -Credential $ScheduledTaskCredential -TaskName $TaskName -Execute $Execute -Argument $Argument -RepetitionIntervalName EveryDayAt6am -ComputerName $ComputerName
        }
    }
}

function Set-TervisEBSRemoteAppFileAssociations {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            New-Item -Path HKLM:\SOFTWARE\Classes\jpegfile\shell -Name Open
            Set-ItemProperty -Path HKLM:\SOFTWARE\Classes\jpegfile\shell\Open -Name "(Default)" -Value "Open" -Type String 
            New-Item -Path HKLM:\SOFTWARE\Classes\jpegfile\shell\Open -Name command
            Set-ItemProperty -Path HKLM:\SOFTWARE\Classes\jpegfile\shell\Open\command -Name "(Default)" -Value '"C:\Windows\system32\mspaint.exe" "%1"' -Type String
        }
    }    
}

function Set-TervisEBSDiscovererMiscellaneousSettings {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    begin {
        $JavaDeploymentPathLocal = "C:\Windows\Sun\Java\Deployment"
    }
    process {
        $JavaDeploymentPathRemote = $JavaDeploymentPathLocal | ConvertTo-RemotePath -ComputerName $ComputerName
        Copy-Item -Path \\$env:USERDNSDOMAIN\applications\PowerShell\JavaCerts\trusted.certs -Destination $JavaDeploymentPathRemote
        if (-not (Test-Path -Path $JavaDeploymentPathRemote\deployment.config)) {
            Invoke-Command -ComputerName $ComputerName -ScriptBlock {
                "`ndeployment.system.security.trusted.certs=C\:\\Windows\\Sun\\Java\\Deployment\\trusted.certs" | Out-File $using:JavaDeploymentPathLocal\deployment.properties -Append -Encoding ascii
                "deployment.system.config=file\:C\:/Windows/Sun/Java/Deployment/deployment.properties" | Out-File $using:JavaDeploymentPathLocal\deployment.config -Encoding ascii
            }
        }
    }    
}

function Disable-AdobeScheduledTasks {
    param (
        [Parameter(Mandatory,ValueFromPipelineByPropertyName)]$ComputerName
    )
    process {
        Invoke-Command -ComputerName $ComputerName -ScriptBlock {
            Disable-ScheduledTask -TaskName *Adobe*
        }
    }    
}
