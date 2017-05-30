function Invoke-RemoteWebBrowserAppProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName RemoteWebBrowserApp -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName RemoteWebBrowserApp -EnvironmentName $EnvironmentName
    $Nodes | Add-TervisRdsServer
    $Nodes | Add-TervisRdsSessionHost
    $Nodes | New-TervisRdsSessionCollection
}

function Invoke-StoresRemoteDesktopProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName StoresRemoteDesktop -EnvironmentName $EnvironmentName
    $Nodes = Get-TervisClusterApplicationNode -ClusterApplicationName StoresRemoteDesktop -EnvironmentName $EnvironmentName
    $CollectionSecurityGroup = (Get-ADDomain).NetBIOSName + '\Privilege_StoresRDS_RemoteDesktop'
    $Nodes | New-TervisRdsSessionCollection -CollectionSecurityGroup $CollectionSecurityGroup -CollectionDescription 'Stores Remote Desktop Services'
    $Nodes | Add-TervisRdsSessionHost
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
        [Parameter(ValueFromPipelineByPropertyName)]$ClusterApplicationName,
        [Parameter(Mandatory)]$CollectionSecurityGroup,
        [Parameter(Mandatory)]$CollectionDescription
    )
    Begin {
        $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    Process {
        If (-NOT (Get-RDSessionCollection -ConnectionBroker $RDBroker -CollectionName $ClusterApplicationName -ErrorAction SilentlyContinue)) {
            $SessionHost = $ComputerName + '.' + $DNSRoot
            New-RDSessionCollection -CollectionName $ClusterApplicationName -ConnectionBroker $RDBroker -SessionHost $SessionHost -CollectionDescription $CollectionDescription
            Set-RDSessionCollectionConfiguration `
                -ConnectionBroker $RDBroker `
                -CollectionName $ClusterApplicationName `
                -UserGroup $CollectionSecurityGroup `
                -DisconnectedSessionLimitMin 720 `
                -IdleSessionLimitMin 720 `
                -AutomaticReconnectionEnabled $true
        }
    }
}

function Add-TervisRdsSessionHost {
    param (
        [Parameter(ValueFromPipelineByPropertyName)]$ComputerName,
        [Parameter(ValueFromPipelineByPropertyName)]$ClusterApplicationName
    )
    Begin {
        $RDBroker = Get-ADComputer -filter 'Name -like "*broker*"' | Select -ExpandProperty DNSHostName
        $DNSRoot = Get-ADDomain | Select -ExpandProperty DNSRoot
    }
    Process {
        If (-NOT ((Get-RDSessionHost -CollectionName $ClusterApplicationName -ConnectionBroker $RDBroker -ErrorAction SilentlyContinue) -contains $ComputerName)) {
            $SessionHost = $ComputerName + '.' + $DNSRoot
            Add-RDSessionHost -CollectionName $ClusterApplicationName -SessionHost $SessionHost -ConnectionBroker $RDBroker
        }
    }
}