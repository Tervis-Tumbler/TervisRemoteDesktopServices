# This script is used with a logon script GPO to automatically pin the local
# user profile to the remote session. 

$Username = $env:Username
$OneDrivePath = "\\tsclient\c\users\$($Username)\OneDrive - Tervis"
$NonOneDrivePath = "\\tsclient\c\users\$($Username)"
$ShellObject = New-Object -ComObject shell.application

if (Test-Path -Path $OneDrivePath) {
    $CurrentPath = $OneDrivePath
} elseif (Test-Path -Path $NonOneDrivePath) {
    $CurrentPath = $NonOneDrivePath
} else {
    break
}

$ShellObject.Namespace($CurrentPath).Self.InvokeVerb("pintohome")