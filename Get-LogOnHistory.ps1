[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $Username
    ,
    [Parameter()]
    [datetime]
    $StartDate
    ,
    [Parameter()]
    [datetime]
    $EndDate
    ,
    [Parameter()]
    [switch]
    $IncludeLogOff
    ,
    [Parameter()]
    [string]
    $ComputerName = $env:COMPUTERNAME
)

# Default event ID filter. 4624 = Logon event.
$eventID = [System.Collections.ArrayList]@('4624')

# If IncludeLogOff is specified, add event 4634 to the filter
if ($IncludeLogOff) {
    $null = $eventID.Add('4634')
}

# Base filter
$filter = @{
    LogName      = 'Security'
    ID           = $eventID
    ProviderName = 'Microsoft-Windows-Security-Auditing'
}

# If StartDate is specified
if ($StartDate) {
    $filter.Add('StartDate', $StartDate)
}

# If EndDate is specified
if ($EndDate) {
    $filter.Add('StartDate', $EndDate)
}

# Add username filter
if ($Username) {
    ## If PowerShell Core
    if ($PSVersionTable.PSEdition -eq 'Core') {
        $filter.Add('TargetUserName', $Username)
    }
    ## If Windows PowerShell
    else {
        $filter.Add('Data', $Username)
    }
}

try {
    $events = Get-WinEvent -FilterHashtable $filter -ErrorAction Stop -ComputerName $ComputerName

    foreach ($event in $events) {
        [PSCustomObject]@{
            TimeStamp    = $event.TimeCreated
            EventType    = $(
                if ($event.Id -eq '4624') {
                    'LogOn'
                }
                else {
                    'LogOff'
                }
            )
            User         = $(
                if ($Username) {
                    $Username
                }
                elseif ($event.Id -eq '4624') {
                    $event.Properties[5].Value
                }
                else {
                    $event.Properties[1].Value
                }
            )
            SourceIP     = $(
                if ($event.Id -eq '4624') {
                    $event.Properties[18].Value
                }
                else {
                    $null
                }
            )
            ComputerName = $ComputerName
        }
    }
}
catch {
    $_.Exception.Message | Out-Default
    return $null
}