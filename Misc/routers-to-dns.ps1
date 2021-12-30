#IPv4
Remove-Item C:\Temp\Git\Misc\Output\bbdns.txt
$output_v4 = $null
$output_v4 += "name,ip`n"
Get-ChildItem "C:\Temp\Git\Misc\Ipv4" | 
Foreach-Object {
    $hostname = $_.Name
    $content = Get-Content $_.FullName
    $vrf = $null
    $interface = $null
    $ipv4 = $null
    foreach ($line in $content){
    if(!$line)
    {
        continue
    }
    if($line -like '*VRF*')
        {
            #$line.Replace('IP Interface Status for VRF','')
            #$line.Split('"')
            #$line2 = $line.Replace("`"","$")
            $line2 = $line.split("`"")
            $vrf = $line2[1]
            #$vrf
            continue
            
        }
    #Nutzlose lines raus
    if ($line -like '*Interface*')
    {
        continue
    }
    if ($line -like '*mgmt0*')
    {
        continue
    }
    if ($line -like '*forward-enabled*')
    {
        continue
    }
    #hier ist die ip versteckt
    if($line -like '*protocol-up*')
        {
            $line3 = $line.split(' ')
            $interface = $line3[0]
            if($interface -like '*/*')
            {
                $interface = $interface.Replace('/', '-')
            }
            if($interface -like '*.*')
            {
                $interface = $interface.Replace('.', '_')
            }

            foreach ($zelle in $line3)
                {
                    If ($zelle -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" ) { $ipv4 = $zelle}
                }


        }
        $output_v4 += $interface
        $output_v4 += '.'
        $output_v4 += $vrf
        $output_v4 += '.'
        $output_v4 += $hostname
        $output_v4 += ','
        $output_v4 += $ipv4
        $output_v4 += "`n"
        #write-host $interface $vrf $hostname $ipv4
        #write-host $hostname + ' ' + $vrf + ' ' + $interface + ' ' + $ipv4
    
    }
}

$output_v4 | Set-content C:\Temp\Git\Misc\Output\bbdns.txt
#$output_v4
#IPv6


Remove-Item C:\Temp\Git\Misc\Output\bb6dns.txt
$output_v6 = $null
$output_v6 += "name,ip`n"
Get-ChildItem "C:\Temp\Git\Misc\Ipv6" | 
Foreach-Object {
    $hostname = $_.Name
    $content = Get-Content $_.FullName
    $vrf = $null
    $interface = $null
    $ipv6 = $null
    foreach ($line in $content){
    if(!$line)
    {
        continue
    }
    if($line -like '*VRF*')
        {
            #$line.Replace('IP Interface Status for VRF','')
            #$line.Split('"')
            #$line2 = $line.Replace("`"","$")
            $line2 = $line.split("`"")
            $vrf = $line2[1]
            #$vrf
            continue
            
        }
        #nutzlose lines raus
    if ($line -like '*Interface*')
    {
        continue
    }
    if ($line -like '*prot/link/admin*')
    {
        continue
    }
    if ($line -like '*mgmt0*')
    {
        continue
    }
    if ($line -like '*fe80*')
    {
        continue
    }
    #hier ist die ip versteckt
    if($line -like '*up/up/up*')
        {
            $line3 = $line.split(' ')
            $interface = $line3[0]
            if($interface -like '*/*')
            {
                $interface = $interface.Replace('/', '-')
            }
            if($interface -like '*.*')
            {
                $interface = $interface.Replace('.', '_')
            }

            foreach ($zelle in $line3)
                {
                    If ($zelle -like '*2a0c*') { $ipv6 = $zelle}
                }


        }
        $output_v6 += $interface
        $output_v6 += '.'
        $output_v6 += $vrf
        $output_v6 += '.'
        $output_v6 += $hostname
        $output_v6 += ','
        $output_v6 += $ipv6
        $output_v6 += "`n"
        #write-host $interface $vrf $hostname $ipv6
        #write-host $hostname + ' ' + $vrf + ' ' + $interface + ' ' + $ipv4
    
    }
}

$output_v6 | Set-content C:\Temp\Git\Misc\Output\bb6dns.txt

#fabric v4

Remove-Item C:\Temp\Git\Misc\Output\fdns.txt
$output_fv4 = $null

Get-ChildItem "C:\Temp\Git\Misc\Fabric\Ipv4" | 
Foreach-Object {
    $hostname = $_.Name
    $content = Get-Content $_.FullName
    $vrf = $null
    $interface = $null
    $ipv4 = $null
    foreach ($line in $content){
    if(!$line)
    {
        continue
    }
    if($line -like '*VRF*')
        {
            #$line.Replace('IP Interface Status for VRF','')
            #$line.Split('"')
            #$line2 = $line.Replace("`"","$")
            $line2 = $line.split("`"")
            $vrf = $line2[1]
            #$vrf
            continue
            
        }
    #Nutzlose lines raus
    if ($line -like '*Interface*')
    {
        continue
    }
    if ($line -like '*forward-enabled*')
    {
        continue
    }
    if ($line -like '*mgmt0*')
    {
        continue
    }
    #hier ist die ip versteckt
    if($line -like '*protocol-up*')
        {
            $line3 = $line.split(' ')
            $interface = $line3[0]
            if($interface -like '*/*')
            {
                $interface = $interface.Replace('/', '-')
            }
            if($interface -like '*.*')
            {
                $interface = $interface.Replace('.', '_')
            }

            foreach ($zelle in $line3)
                {
                    If ($zelle -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" ) { $ipv4 = $zelle}
                }


        }
        $output_fv4 += $interface
        $output_fv4 += '.'
        $output_fv4 += $vrf
        $output_fv4 += '.'
        if(($interface -like '*Vlan*') -and (!($interface -like '*Vlan1000*')))
        {
        $output_fv4 += 'Anycast.Fabric'
        }else{
        $output_fv4 += $hostname
        }
        $output_fv4 += ','
        $output_fv4 += $ipv4
        $output_fv4 += "`r`n"
        #write-host $interface $vrf $hostname $ipv4
        #write-host $hostname + ' ' + $vrf + ' ' + $interface + ' ' + $ipv4
    
    }
}
#$output_fv4 += "name,ip`n"


$output_fv4 | Set-content C:\Temp\Git\Misc\Output\fdns.txt
Get-Content C:\Temp\Git\Misc\Output\fdns.txt | Sort-Object -Unique | Set-Content C:\Temp\Git\Misc\Output\fdns.txt


#fabric v6





Remove-Item C:\Temp\Git\Misc\Output\f6dns.txt
$output_fv6 = $null
#$output_fv6 += "name,ip`n"
Get-ChildItem "C:\Temp\Git\Misc\Fabric\Ipv6" | 
Foreach-Object {
    $hostname = $_.Name
    $content = Get-Content $_.FullName
    $vrf = $null
    $interface = $null
    $ipv6 = $null
    foreach ($line in $content){
    if(!$line)
    {
        continue
    }
    if($line -like '*VRF*')
        {
            #$line.Replace('IP Interface Status for VRF','')
            #$line.Split('"')
            #$line2 = $line.Replace("`"","$")
            $line2 = $line.split("`"")
            $vrf = $line2[1]
            #$vrf
            continue
            
        }
        #nutzlose lines raus
    if ($line -like '*Interface*')
    {
        continue
    }
    if ($line -like '*prot/link/admin*')
    {
        continue
    }
    if ($line -like '*fe80*')
    {
        continue
    }
    if ($line -like '*mgmt0*')
    {
        continue
    }
    #hier ist die ip versteckt
    if($line -like '*up/up/up*')
        {
            $line3 = $line.split(' ')
            $interface = $line3[0]
            if($interface -like '*/*')
            {
                $interface = $interface.Replace('/', '-')
            }
            if($interface -like '*.*')
            {
                $interface = $interface.Replace('.', '_')
            }

            foreach ($zelle in $line3)
                {
                    If ($zelle -like '*2a0c*') { $ipv6 = $zelle}
                }


        }
        $output_fv6 += $interface
        $output_fv6 += '.'
        $output_fv6 += $vrf
        $output_fv6 += '.'
        if(($interface -like '*Vlan*') -and (!($interface -like '*Vlan1000*')))
        {
        $output_fv6 += 'Anycast.Fabric'
        }else{
        $output_fv6 += $hostname
        }
        $output_fv6 += ','
        $output_fv6 += $ipv6
        $output_fv6 += "`n"
        #write-host $interface $vrf $hostname $ipv6
        #write-host $hostname + ' ' + $vrf + ' ' + $interface + ' ' + $ipv4
    
    }
}

$output_fv6 | Set-content C:\Temp\Git\Misc\Output\f6dns.txt
Get-Content C:\Temp\Git\Misc\Output\f6dns.txt | Sort-Object -Unique | Set-Content C:\Temp\Git\Misc\Output\f6dns.txt

#Fortigate