# Get-LogOnHistory.ps1
[CmdletBinding()]
param (
    [Parameter()]
    [String]
    $Username
    ,
    [Parameter()]
    [datetime]
    $StartTime
    ,
    [Parameter()]
    [datetime]
    $EndTime
    ,
    [Parameter()]
    [switch]
    $IncludeLogOff
    ,
    [Parameter()]
    [string]
    $ComputerName = $env:COMPUTERNAME
)

# Base filter
$filter = @{
    LogName      = 'Security'
    ID           = @('4624')
    ProviderName = 'Microsoft-Windows-Security-Auditing'
}

# If IncludeLogOff is specified, add event 4634 to the filter
if ($IncludeLogOff) {
    $filter['ID'] += '4634'
}

# If StartDate is specified
if ($StartTime) {
    $filter.Add('StartTime', $StartTime)
}

# If EndDate is specified
if ($EndTime) {
    $filter.Add('EndTime', $EndTime)
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

# https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-logon-events#configure-this-audit-setting
$logOnTypeTable = @{
    '2'  = 'Interactive'
    '3'  = 'Network'
    '4'  = 'Batch'
    '5'  = 'Service'
    '6'  = 'Unlock'
    '7'  = 'NetworkCleartext'
    '8'  = 'NewCredentials'
    '9'  = 'RemoteInteractive'
    '10' = 'RemoteInteractive'
    '11' = 'CachedInteractive'
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
            LogOnType    = $logOnTypeTable["$($event.Properties[8].value)"]
        }
    }
}
catch {
    $_.Exception.Message | Out-Default
    return $null
}