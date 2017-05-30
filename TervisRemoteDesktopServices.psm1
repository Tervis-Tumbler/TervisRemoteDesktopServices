function Invoke-RemoteWebBrowserAppProvision {
    param (
        $EnvironmentName
    )
    Invoke-ClusterApplicationProvision -ClusterApplicationName RemoteWebBrowserApp -EnvironmentName $EnvironmentName
}