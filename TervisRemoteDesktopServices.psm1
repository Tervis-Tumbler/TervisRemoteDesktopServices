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
        $RemoteDesktopRDPContent | Out-File -FilePath $RDPFileName -NoNewline -Encoding ascii
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
