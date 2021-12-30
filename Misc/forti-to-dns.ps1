$output_v4 = $null
$output_v4 += "name,ip`n"
Get-ChildItem "C:\Temp\Git\Misc\FW" | 
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

    if($line -like '*edit*')
        {
            $line2 = $line.split("`"")
            $interface = $line2[1]
            #$interface
            continue
            
        }elseif($line -like '*vdom*'){
            $work = $null
            $work = $line.Split(' ')
            $vrf = $work[10]
            $vrf = $vrf.replace("`"",'')
            #write-host $interface $vrf $hostname $ipv4
            continue
            
        }elseif($line -like '*set ip *')
        {
            $work = $null
            $work = $line.Split(' ')
            $ipv4 = $work[10]
            #write-host $interface $vrf $hostname $ipv4
            if($ipv4 -eq ""){
                write-host $ipv4
                continue}
            $output_v4 += $interface
            $output_v4 += '.'
            $output_v4 += $vrf
            $output_v4 += '.'
            $output_v4 += $hostname
            $output_v4 += ','
            $output_v4 += $ipv4
            $output_v4 += "`n"
            continue
        }elseif($line -like '*next*'){
            
            $interface = $null
            $vrf = $null
            $ipv4 = $null

        }elseif($line -like '*tunnel*'){
            
            $interface = $null
            $vrf = $null
            $ipv4 = $null
            continue
        
        }else{continue}
    #Nutzlose lines raus
    
#        $output_v4 += $interface
#        $output_v4 += '.'
#        $output_v4 += $vrf
#        $output_v4 += '.'
#        $output_v4 += $hostname
#        $output_v4 += ','
#        $output_v4 += $ipv4
#        $output_v4 += "`n"

        
        
    
    }
}
$output_v4 | Set-content C:\Temp\Git\Misc\FW\\dns.txt


$output_v6 = $null
Get-ChildItem "C:\Temp\Git\Misc\FW" | 
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

    if($line -like '*edit*')
        {
            $line2 = $line.split("`"")
            $interface = $line2[1]
            #$interface
            continue
            
        }elseif($line -like '*vdom*'){
            $work = $null
            $work = $line.Split(' ')
            $vrf = $work[10]
            $vrf = $vrf.replace("`"",'')
            #write-host $interface $vrf $hostname $ipv4
            continue
            
        }elseif($line -like '*ip6-address *')
        {
            $work = $null
            $work = $line.Split(' ')
            
            $work = $work[14]
            $work = $work.split('/')
            $ipv6 = $work[0]
            #write-host $interface $vrf $hostname $ipv4
            $output_v6 += $interface
            $output_v6 += '.'
            $output_v6 += $vrf
            $output_v6 += '.'
            $output_v6 += $hostname
            $output_v6 += ','
            $output_v6 += $ipv6
            $output_v6 += "`n"
            continue
        }elseif($line -like '*next*'){
            
            $interface = $null
            $vrf = $null
            $ipv6 = $null

        }elseif($line -like '*tunnel*'){
            
            $interface = $null
            $vrf = $null
            $ipv6 = $null
            continue
        
        }else{continue}
    #Nutzlose lines raus
    
#        $output_v4 += $interface
#        $output_v4 += '.'
#        $output_v4 += $vrf
#        $output_v4 += '.'
#        $output_v4 += $hostname
#        $output_v4 += ','
#        $output_v4 += $ipv4
#        $output_v4 += "`n"

        
        
    
    }
}
#$output_v6
$output_v6 | Set-content C:\Temp\Git\Misc\FW\dns6.txt