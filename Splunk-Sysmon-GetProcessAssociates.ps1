
function get-search-results {

    param ($cred, $server, $port, $search)

    # This will allow for self-signed SSL certs to work
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12   #(ssl3,SystemDefault,Tls,Tls11,Tls12)

    $url = "https://${server}:${port}/services/search/jobs/export" # braces needed b/c the colon is otherwise a scope operator
    $the_search = "search $($search)" # Cmdlet handles urlencoding
    $body = @{
        search = $the_search
        output_mode = "csv"
          }
    
    $SearchResults = Invoke-RestMethod -Method Post -Uri $url -Credential $cred -Body $body -TimeoutSec 300
    return $SearchResults
}



$hostname = "basement-pc"
$earliest="03/27/2019:20:42:00" 
$latest="03/27/2019:21:00:00"
$server = "splunk-dev"
$port = "8089"

$cred = Get-Credential -Message "enter splunk cred"



# INTEGRATE INPUTS INTO SEARCH STATEMENT
$search  = "source=`"*WinEventLog:Microsoft-Windows-Sysmon/Operational`" EventCode=1 
    host=$($hostname) 
    earliest=`"$($earliest)`" latest=`"$($latest)`"
    | table _time, host, EventCode, EventDescription, ProcessId, ParentProcessId, User, process, CommandLine, ParentImage, ParentCommandLine, ProcessGuid, ParentProcessGuid
    | sort 0 _time"


# INVOKE SEARCH
write-host "Invoking the following search on $($server):"
write-host $search

$results  = get-search-results -server $server -port $port -cred $cred -search $search
if (!($results)) { 
    write-host "no results found, exiting."
    exit 
}


# PRESENT RESULTS IN GRID VIEW SO USER CAN IDENTIFY TOP LEVEL PROCESS OF CONCERN
$results = ConvertFrom-Csv -InputObject $results
$Selected = $results | Out-GridView -PassThru  -Title 'Select Parent Event of Concern'
if (!$Selected) {
    write-host "nothing selected, exiting."
    exit 
}

# SEARCH CORPUS FOR ALL CHILDREN OF PROCESS OF CONCERN
$ParentProcessGuids = @($selected.ProcessGuid)
$DiscoveredGuids = $ParentProcessGuids
$DescendentEvents = @()
$RecursionLevel = 0

do {
    $blnFoundSome = $False
    ++$RecursionLevel

    $ProcessGuids = @()

    foreach ($Result in $Results) {

        if ($ParentProcessGuids -match $result.ParentProcessGuid) {
            $blnFoundSome = $True

            $CurrentEvent = @()
            $CurrentEvent = $Result
            $CurrentEvent | Add-Member -MemberType NoteProperty "Level" -Value $RecursionLevel

            $DescendentEvents += $CurrentEvent   

            $ProcessGuids += $result.ProcessGuid
        }
    }

    $ProcessGuids  = $ProcessGuids | Select-Object -Unique
    Write-Host "Completed loop $($RecursionLevel) and found $($ProcessGuids.count) new process guids within $($DescendentEvents.count) events."

    $DiscoveredGuids += $ProcessGuids
    $ParentProcessGuids = $ProcessGuids

} until ($blnFoundSome -eq $False)

Write-Host "Discovered a total of $($DiscoveredGuids.count) guids."


# NOW THAT WE HAVE ALL THESE GUIDS, WE COULD GO FURTHER TO FIND ALL OTHER CLASSES OF SYSMON EVENTS RELATING TO THEM
#$DescendentEvents | Out-GridView


# TURN GUID ARRAY INTO SEARCH FILTER
$searchfilter_fields = "("
foreach ($DiscoveredGuid in $DiscoveredGuids) {
    if ($searchfilter_fields -eq "(") {
        $searchfilter_fields = "(ProcessGuid=`"$($DiscoveredGuid)`""
    } else {
        $searchfilter_fields += " OR ProcessGuid=`"$($DiscoveredGuid)`""
    }
}
$searchfilter_fields += ")"
#$searchfilter_raw = $searchfilter -replace "ProcessGuid=",""
#$searchfilter = "$($searchfilter_raw) AND $($searchfilter_fields)"



# INTEGRATE INPUTS INTO SEARCH STATEMENT
$search = $search -replace "EventCode=1",$searchfilter_fields
# INVOKE SEARCH
write-host "Invoking search on $($server)..."
#write-host "$($search)"
$results  = get-search-results -server $server -port $port -cred $cred -search $search
if (!($results)) { 
    write-host "no results found, exiting."
    exit 
}

# PRESENT RESULTS IN GRID VIEW
$results = ConvertFrom-Csv -InputObject $results
$results | Out-GridView -Title "Behold the activity of the parent and it's children!"

<#
# Install GraphViz from the Chocolatey repo
Find-Package graphviz | Install-Package -ForceBootstrap

# Install PSGraph from the Powershell Gallery
Find-Module PSGraph | Install-Module
#>

<#
# Import Module
Import-Module PSGraph

$process = $results | ?{$_.EventCode -eq 1}
#$process = $process -replace "\\","\\"

write-host $process[0]

$thing = graph processes @{rankdir='LR'} {
    node @{shape='box'}
    node $process -NodeScript {$_.ProcessGuid} -Attributes @{label={"$($_.Process):$($_.ProcessId)`n$($_.User)`n$($_.CommandLine)"}}
    edge $process -FromScript {$_.ParentProcessGuid} -ToScript {$_.ProcessGuid}
} 

$thing | Export-PSGraph -ShowGraph
#>
