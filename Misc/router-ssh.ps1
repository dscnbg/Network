function Get-IniContent ($filePath)
{
    $ini = @{}
    switch -regex -file $FilePath
    {
        “^\[(.+)\]” # Section
        {
            $section = $matches[1]
            $ini[$section] = @{}
            $CommentCount = 0
        }
        “^(;.*)$” # Comment
        {
            $value = $matches[1]
            $CommentCount = $CommentCount + 1
            $name = “Comment” + $CommentCount
            $ini[$section][$name] = $value
        }
        “(.+?)\s*=(.*)” # Key
        {
            $name,$value = $matches[1..2]
            $ini[$section][$name] = $value
        }
    }
    return $ini
}

$iniContent = Get-IniContent “C:\Temp\Git\Misc\settings.ini”

$username = [string]$iniContent["TAC"]["username"]
$password = [string]$iniContent["TAC"]["password"]

$username = $username -replace ' ',''
$password = $password -replace ' ',''

$fabricuser = $iniContent["FABRIC"]["username"]
$fabricpasswd = $iniContent["FABRIC"]["password"]

$fabricuser = $fabricuser -replace ' ',''
$fabricpasswd = $fabricpasswd -replace ' ',''

$BBrouters = [string]$iniContent["ROUTERS"]["bbrouters"]
$BBrouters = $BBrouters -replace ' ',''
$BBrouters = $BBrouters -split ","

$BBohneTAC = [string]$iniContent["ROUTERS"]["bbohnetac"]
$BBohneTAC = $BBohneTAC -replace ' ',''
$BBohneTAC = $BBohneTAC -split ","

$fabric = [string]$iniContent["ROUTERS"]["fabric"]
$fabric = $fabric -replace ' ',''
$fabric = $fabric -split ","

$iosxe = [string]$iniContent["ROUTERS"]["iosxe"]
$iosxe = $iosxe -replace ' ',''
$iosxe = $iosxe -split ","

$fortiPasswd = ConvertTo-SecureString $password -AsPlainText -Force
$credential = New-Object System.Management.Automation.PSCredential ($username, $fortiPasswd)


$fabriccredpw = ConvertTo-SecureString $fabricpasswd -AsPlainText -Force
$fabriccred = New-Object System.Management.Automation.PSCredential ($fabricuser, $fabriccredpw)

#iosxe

#foreach($fortiIp in $iosxe){
#
#$sshSession = New-SSHsession -Computername $fortiIp -credential $credential
#
#$command = @"
#show ipv6 interface brief
#"@
#
#
#$command2 = @"
#show run | i hostname
#"@
#
#$command3 = @"
#show ip interface brief
#"@
#
#$sshSession
#
#$hostname = $null
#$result = $null
#$result = Invoke-SSHCommand -Command $command -SessionId $sshSession.SessionId
#$result2 = $null
#$result2 = Invoke-SSHCommand -Command $command2 -SessionId $sshSession.SessionId
#$result3 = $null
#$result3 = Invoke-SSHCommand -Command $command3 -SessionId $sshSession.SessionId
#
#foreach($zeile in $result2.Output){
#    if($zeile -contains "hostname "){
#        $hostname = $zeile -replace 'hostname ',''
#    }
#}
#
#
#write-host $hostname
#
#}
#
#exit


# Backbone
foreach($fortiIp in $BBrouters){

$sshSession = New-SSHsession -Computername $fortiIp -credential $credential

$command = @"
show ipv6 interface brief vrf all
"@


$command2 = @"
show hostname
"@

$command3 = @"
show ip interface brief vrf all
"@

$sshSession

$result = $null
$result = Invoke-SSHCommand -Command $command -SessionId $sshSession.SessionId
$result2 = $null
$result2 = Invoke-SSHCommand -Command $command2 -SessionId $sshSession.SessionId
$result3 = $null
$result3 = Invoke-SSHCommand -Command $command3 -SessionId $sshSession.SessionId

$hostname = $result2.Output
$hostname = $hostname[0].ToString()
$hostname.Trim()
$result.Output | Out-File C:\Temp\Git\Misc\Ipv6\$hostname
$result3.Output | Out-File C:\Temp\Git\Misc\Ipv4\$hostname

remove-sshsession -index 0 -verbose
}
$fortiIp = $null

# Fabric
foreach($fortiIp in $fabric){

$sshSession = New-SSHsession -Computername $fortiIp -credential $fabriccred

$command = @"
show ipv6 interface brief vrf all
"@


$command2 = @"
show hostname
"@

$command3 = @"
show ip interface brief vrf all
"@

$sshSession

$result = $null
$result = Invoke-SSHCommand -Command $command -SessionId $sshSession.SessionId
$result2 = $null
$result2 = Invoke-SSHCommand -Command $command2 -SessionId $sshSession.SessionId
$result3 = $null
$result3 = Invoke-SSHCommand -Command $command3 -SessionId $sshSession.SessionId


#$result.Output
$hostname = $result2.Output
$hostname = $hostname[0].ToString()
$hostname.Trim()
$result.Output | Out-File C:\Temp\Git\Misc\Fabric\Ipv6\$hostname
$result3.Output | Out-File C:\Temp\Git\Misc\Fabric\Ipv4\$hostname

remove-sshsession -index 0 -verbose
}

$fortiIp = $null

# BB ohne TAC
foreach($fortiIp in $BBohneTAC){

$sshSession = New-SSHsession -Computername $fortiIp -credential $fabriccred

$command = @"
show ipv6 interface brief vrf all
"@


$command2 = @"
show hostname
"@

$command3 = @"
show ip interface brief vrf all
"@

$sshSession

$result = $null
$result = Invoke-SSHCommand -Command $command -SessionId $sshSession.SessionId
$result2 = $null
$result2 = Invoke-SSHCommand -Command $command2 -SessionId $sshSession.SessionId
$result3 = $null
$result3 = Invoke-SSHCommand -Command $command3 -SessionId $sshSession.SessionId


#$result.Output
$hostname = $result2.Output
$hostname = $hostname[0].ToString()
$hostname.Trim()
$result.Output | Out-File C:\Temp\Git\Misc\Ipv6\$hostname
$result3.Output | Out-File C:\Temp\Git\Misc\Ipv4\$hostname

remove-sshsession -index 0 -verbose
}


#Fortigate

$fortigate = "10.110.121.101"

$fgtpasswd = ConvertTo-SecureString $fabricpasswd -AsPlainText -Force

$credential = New-Object System.Management.Automation.PSCredential ($fabricuser, $fgtpasswd)

$sshSession = New-SSHsession -Computername $fortigate -credential $credential


$command = @"
config global
config system interface
show
"@


$sshSession
$result = $null
$result = Invoke-SSHCommand -Command $command -SessionId $sshSession.SessionId
$result.Output | Out-File C:\Temp\Git\Misc\FW\DOP-FWC-DEFRA001

remove-sshsession -index 0 -verbose