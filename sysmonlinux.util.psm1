function Get-SysmonLinuxEvent {
    <#
    .SYNOPSIS
        Gets one or more Sysmon for Linux event types from Syslog logs.
    .DESCRIPTION
        Gets one or more Sysmon for Linux event types from Syslog logs. Allows for filtering by ProcessGUID and User. 
    .EXAMPLE
        PS /> Get-SysmonLinuxEvent -EventType Any -ProcessGuid "{de9527a5-6a3f-616f-a52f-d98154560000}" 

        EventId           : 1
        Version           : 5
        EventType         : ProcessCreate
        Computer          : ubuntu
        EventRecordID     : 35705
        RuleName          : -
        UtcTime           : 2021-10-20 01:00:47.600
        ProcessGuid       : {de9527a5-6a3f-616f-a52f-d98154560000}
        ProcessId         : 2356
        Image             : /usr/sbin/dumpe2fs
        FileVersion       : -
        Description       : -
        Product           : -
        Company           : -
        OriginalFileName  : -
        CommandLine       : dumpe2fs -h /dev/sda5
        CurrentDirectory  : /
        User              : root
        LogonGuid         : {de9527a5-0000-0000-0000-000000000000}
        LogonId           : 0
        TerminalSessionId : 4294967295
        IntegrityLevel    : no level
        Hashes            : -
        ParentProcessGuid : {00000000-0000-0000-0000-000000000000}
        ParentProcessId   : 874
        ParentImage       : -
        ParentCommandLine : -
        ParentUser        : -

        EventId       : 9
        Version       : 2
        EventType     : RawAccessRead
        Computer      : ubuntu
        EventRecordID : 35706
        RuleName      : -
        UtcTime       : 2021-10-20 01:00:47.619
        ProcessGuid   : {de9527a5-6a3f-616f-a52f-d98154560000}
        ProcessId     : 2356
        Image         : /usr/sbin/dumpe2fs
        Device        : /dev/sda5
        User          : root

        EventId       : 5
        Version       : 3
        EventType     : ProcessTerminate
        Computer      : ubuntu
        EventRecordID : 35707
        RuleName      : -
        UtcTime       : 2021-10-20 01:00:47.620
        ProcessGuid   : {de9527a5-6a3f-616f-a52f-d98154560000}
        ProcessId     : 2356
        Image         : /usr/sbin/dumpe2fs
        User          : root

        Find all events that match the specified ProcessGuid.
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param (
        # Event type to pull from Syslog log file.
        [Parameter(Mandatory=$True)]
        [ValidateSet("Any","ProcessCreate","ProcessTerminate","NetworkConnect",
            "SysmonState","RawAccessRead","FileCreate","ConfigChange","FileDelete")]
        [string[]]
        $EventType,

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # ProcessGuid to search for a given event type, ParentProcessGuid will also be matched to this value.
        [Parameter(Mandatory=$false,
            ParameterSetName="Guid")]
        [string[]]
        $ProcessGuid,

        # Image to search for a given event type.The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $Image,

        # User to seach for a given event type.
        [Parameter(Mandatory=$false)]
        [string[]]
        $User

    )
    
    begin {
        $EventTypetoId = @{
            'ProcessCreate' = '1'
            'NetworkConnect' = '3'
            'SysmonState' = '4'
            'ProcessTerminate' = '5'
            'RawAccessRead' = '9'
            'FileCreate' = '11'
            'FileDelete' = '23'
            'ConfigChange' = '16'
            'Any' = @('1','3','4','5','9','11','23','16')
        }

        $EventIdtoType = @{
            '1' = 'ProcessCreate'
            '2' = 'FileCreateTime'
            '3' = 'NetworkConnect'
            '4' = 'StateChange'
            '5' = 'ProcessTerminate'
            '9' = 'RawAccessRead'
            '11' = 'FileCreate'
            '16' = 'ConfigChange'
            '23' = 'FileDelete'
        }

        # Create EventType pattern.
        $eventToQ = @()
        foreach ($etype in $EventType) {
            $eventToQ += $EventTypetoId[$etype]
        }
        $eventids = $eventToQ -join "|"
        write-verbose -message "Searching for events $($eventids)"
        $pattern = "^.*sysmon:.*<EventID>($($eventids))<\/EventID>"

        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"(ProcessGuid|ParentProcessGuid)`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($Image.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=\`"Image\`">($(($Image -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($User.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"User`">($($User))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            $evtxml = [xml]($_.line.split("sysmon:"))[1]
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "$($EventIdtoType[$([string]$evtxml.Event.System.EventID)] )"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.$($EventIdtoType[$([string]$evtxml.Event.System.EventID)] )"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxProcessCreate {
    <#
    .SYNOPSIS
        Gets Sysmon process creation events from Syslog logs.
    .DESCRIPTION
        Gets Sysmon Process creation events from Syslog logs.It allows filtering by field content.
    .EXAMPLE
        PS /> ls syslog* | Get-SysmonLinuxProcessCreate -Image */ping,*/whoami,*/id

        EventId           : 1
        Version           : 5
        EventType         : ProcessCreate
        Computer          : ubuntu
        EventRecordID     : 7468
        RuleName          : -
        UtcTime           : 2021-10-16 04:51:15.156
        ProcessGuid       : {de9527a5-5a43-616a-312b-c11c7a550000}
        ProcessId         : 8455
        Image             : /usr/bin/ping
        FileVersion       : -
        Description       : -
        Product           : -
        Company           : -
        OriginalFileName  : -
        CommandLine       : ping 8.8.8.8 -c 2
        CurrentDirectory  : /home/carlos/Desktop
        User              : carlos
        LogonGuid         : {de9527a5-0000-0000-e803-000001000000}
        LogonId           : 1000
        TerminalSessionId : 3
        IntegrityLevel    : no level
        Hashes            : -
        ParentProcessGuid : {de9527a5-5a43-616a-f537-ea5ba5550000}
        ParentProcessId   : 8454
        ParentImage       : /usr/bin/dash
        ParentCommandLine : /usr/bin/sh
        ParentUser        : carlos

        EventId           : 1
        Version           : 5
        EventType         : ProcessCreate
        Computer          : ubuntu
        EventRecordID     : 452
        RuleName          : -
        UtcTime           : 2021-10-16 00:45:59.711
        ProcessGuid       : {de9527a5-20c7-616a-e171-bdc707560000}
        ProcessId         : 1740
        Image             : /usr/bin/id
        FileVersion       : -
        Description       : -
        Product           : -
        Company           : -
        OriginalFileName  : -
        CommandLine       : id -un
        CurrentDirectory  : /home/carlos
        User              : carlos
        LogonGuid         : {de9527a5-0000-0000-e803-000001000000}
        LogonId           : 1000
        TerminalSessionId : 2
        IntegrityLevel    : no level
        Hashes            : -
        ParentProcessGuid : {de9527a5-20c7-616a-0507-b18881550000}
        ParentProcessId   : 1726
        ParentImage       : /usr/bin/bash
        ParentCommandLine : /bin/bash
        ParentUser        : carlos


        Find across multiple syslog files events that match the images specified using wildcards.
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # ProcessGuid to search for, one or more can be provided.
        [Parameter(Mandatory=$false,
            ParameterSetName="ProcessGuid")]
        [string[]]
        $ProcessGuid,

        # RuleName to search for the given event type.
        #[Parameter(mandatory=$false)]
        #[string]
        #$RuleName,

        # ProcessID to search for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ProcessId,

        # ProcessGuid to search for, one or more can be provided..
        [Parameter(Mandatory=$false)]
        [string[]]
        $ParentProcessGuid,

        # Logon to search for , one or more can be provided.
        [Parameter(Mandatory=$false,
            ParameterSetName="LogonGuid")]
        [string[]]
        $LogonGuid,

        # LogonId to search for , one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $LogonId,

        # Image to search for this event type.The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $Image,

        # CommandLine to search for this event type.The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $CommandLine,

        # CurrentDirectory to search for a given event type.
        [Parameter(mandatory=$false)]
        [string[]]
        $CurrentDirectory,

        # User to seach for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $User,

        # ParentImage to search for, one or more can be provided.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $ParentImage,

        # ParentProcessId to search for, one or more can be provided.
        [Parameter(mandatory=$false)]
        [string[]]
        $ParentProcessId,

        # ParentCommandLine to search for this event type.The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $ParentCommandLine,

        # TerminalSessionId to search for, one or more can be provided.
        [Parameter(mandatory=$false)]
        [string[]]
        $TerminalSessionId,

        # ParentUser to seach for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ParentUser,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {
  
        $pattern = "^*sysmon:.*<EventID>1<\/EventID>"

        if ($RuleName.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"RuleName`">($($RuleName))<\/Data>"
        }


        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"ProcessGuid`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($ProcessId.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"(ProcessId)`">($($ProcessId -join "|"))<\/Data>"
        }

        if ($Image.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Image`">($(($Image -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($CommandLine.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"CommandLine`">($(($CommandLine -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($CurrentDirectory.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"CurrentDirectory`">($($CurrentDirectory -join "|"))<\/Data>"
        }

        if ($User.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"User`">($($User -join "|"))<\/Data>"
        }

        if ($LogonGuid.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"LogonGuid`">($($LogonGuid -join "|"))<\/Data>"
        }

        if ($LogonId.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"LogonId`">($($LogonId -join "|"))<\/Data>"
        }

        if ($TerminalSessionId.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"TerminalSessionId`">($($TerminalSessionId -join "|"))<\/Data>"
        }

        if ($ParentProcessGuid.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"ParentProcessGuid`">($($ParentProcessGuid -join "|"))<\/Data>"
        }

        if ($ParentProcessId.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"ParentProcessId`">($($ParentProcessId -join "|"))<\/Data>"
        }

        if ($ParentImage.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"ParentImage`">($(($ParentImage -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($ParentCommandLine.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"ParentCommandLine`">($(($ParentCommandLine -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($ParentUser.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"ParentUser`">($($ParentUser -join "|"))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {

        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "ProcessCreate"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.ProcessCreate"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxProcessTerminate {
    <#
    .SYNOPSIS
        Gets Sysmon process termination events from Syslog logs.
    .DESCRIPTION
        Gets Sysmon process termination events from Syslog logs.It allows filtering by field content.
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # ProcessGuid to search for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ProcessGuid,

        # RuleName to search for the given event type.
        #[Parameter(mandatory=$false)]
        #[string]
        #$RuleName,

        # ProcessID to search for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ProcessId,

        # Image to search forthis event type.The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $Image,

        # User to seach for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $User,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {


  
        $pattern = "^*sysmon:.*<EventID>5<\/EventID>"

        if ($RuleName.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"RuleName`">($($RuleName))<\/Data>"
        }


        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"ProcessGuid`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"ProcessGuid`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($Image.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Image`">($(($Image -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($User.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"User`">($($User -join "|"))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "ProcessTerminate"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.ProcessTerminate"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxConfigChange {
    <#
    .SYNOPSIS
        Gets Sysmon config change events from Syslog logs.
    .DESCRIPTION
        Gets Sysmon config change events from Syslog logs.
    .EXAMPLE
        PS /> ls syslog* | Get-SysmonLinuxConfigChange                             

        EventId               : 16
        Version               : 3
        EventType             : ConfigChange
        Computer              : ubuntu
        EventRecordID         : 8044
        UtcTime               : 2021-10-17 14:20:46.867
        Configuration         : ./sysmon.xml
        ConfigurationFileHash : -

        EventId               : 16
        Version               : 3
        EventType             : ConfigChange
        Computer              : ubuntu
        EventRecordID         : 0
        UtcTime               : 2021-10-16 00:43:54.472
        Configuration         : /home/carlos/Desktop/sysmon.xml
        ConfigurationFileHash : -

    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # Configuration file used to configure the service.
        [Parameter(Mandatory=$false)]
        [string]
        $Configuration,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {
  
        $pattern = "^*sysmon:.*<EventID>16<\/EventID>"

        if ($Configuration.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"Configuration`">($($Configuration))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "ConfigChange"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.ConfigChange"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxState {
    <#
    .SYNOPSIS
        Gets Sysmon service state change events from Syslog logs.
    .DESCRIPTION
        Gets Sysmon service state change events from Syslog logs.
    .EXAMPLE
        PS /> ls syslog* | Get-SysmonLinuxState -State Stopped

        EventId       : 4
        Version       : 1.0.0
        EventType     : SysmonState
        Computer      : ubuntu
        EventRecordID : 229
        UtcTime       : 2021-10-16 00:44:07.686
        State         : Stopped
        SchemaVersion : 4.81

        EventId       : 4
        Version       : 1.0.0
        EventType     : SysmonState
        Computer      : ubuntu
        EventRecordID : 2397
        UtcTime       : 2021-10-16 00:49:14.832
        State         : Stopped
        SchemaVersion : 4.81

        EventId       : 4
        Version       : 1.0.0
        EventType     : SysmonState
        Computer      : ubuntu
        EventRecordID : 2471
        UtcTime       : 2021-10-16 00:49:24.198
        State         : Stopped
        SchemaVersion : 4.81

        EventId       : 4
        Version       : 1.0.0
        EventType     : SysmonState
        Computer      : ubuntu
        EventRecordID : 5686
        UtcTime       : 2021-10-16 00:56:49.291
        State         : Stopped
        SchemaVersion : 4.81

    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # State of the service to search for.
        [Parameter(Mandatory=$false)]
        [ValidateSet("Started", "Stopped")]
        [string]
        $State ,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {
  
        $pattern = "^*sysmon:.*<EventID>4<\/EventID>"

        if ($State.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"State`">($($State))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "SysmonState"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.SysmonState"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxFileCreate {
    <#
    .SYNOPSIS
        Gets Sysmon file creation events from Syslog logs.
    .DESCRIPTION
        Gets Sysmon file creation events from Syslog logs.It allows filtering by field content.
    .EXAMPLE
        PS /home/carlos/Desktop> ls syslog* | Get-SysmonLinuxFileCreate -TargetFilename *.sh

        EventId         : 11
        Version         : 2
        EventType       : FileCreate
        Computer        : ubuntu
        EventRecordI    : 3792
        RuleName        : -
        UtcTime         : 2021-10-16 00:50:28.049
        ProcessGuid     : {de9527a5-21d3-616a-f5b7-a09aff550000}
        ProcessId       : 2205
        Image           : /usr/bin/dash
        TargetFilename  : /tmp/apt-key-gpghome.H5mVCI5gcY/gpg.1.sh
        CreationUtcTime : 2021-10-16 00:50:28.049
        User            : _apt

        EventId         : 11
        Version         : 2
        EventType       : FileCreate
        Computer        : ubuntu
        EventRecordID   : 3905
        RuleName        : -
        UtcTime         : 2021-10-16 00:50:28.402
        ProcessGuid     : {de9527a5-21d4-616a-f5d7-d7f930560000}
        ProcessId       : 2264
        Image           : /usr/bin/dash
        TargetFilename  : /tmp/apt-key-gpghome.jP1FNudhMk/gpg.1.sh
        CreationUtcTime : 2021-10-16 00:50:28.402
        User            : _apt

    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # ProcessGuid to search for, one or more can be provided.
        [Parameter(Mandatory=$false,
        ParameterSetName="ProcessGuid")]
        [string[]]
        $ProcessGuid,

        # RuleName to search for the given event type.
        #[Parameter(mandatory=$false)]
        #[string]
        #$RuleName,

        # ProcessID to search for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ProcessId,

        # Image to search for, one or more can be provided. The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [string[]]
        $Image,

        # TargetFilename to search for, one or more can be provided. The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $TargetFilename,

        # User to seach for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $User,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {
  
        $pattern = "^*sysmon:.*<EventID>11<\/EventID>"

        if ($RuleName.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"RuleName`">($($RuleName))<\/Data>"
        }


        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"ProcessGuid`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"(ProcessId)`">($($ProcessId -join "|"))<\/Data>"
        }

        if ($Image.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Image`">($(($Image -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($TargetFilename.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"TargetFilename`">($(($TargetFilename -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "FileCreate"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.FileCreate"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxFileDelete {
    <#
    .SYNOPSIS
        Gets Sysmon file deletion events from Syslog logs.
    .DESCRIPTION
        Gets Sysmon file deletion events from Syslog logs.It allows filtering by field content.
    .EXAMPLE
        PS /> Get-SysmonLinuxFileDelete -TargetFilename *.log

        EventId        : 23
        Version        : 5
        EventType      : FileDelete
        Computer       : ubuntu
        EventRecordID  : 41011
        RuleName       : -
        UtcTime        : 2021-10-20 03:11:31.597
        ProcessGuid    : {de9527a5-88e3-616f-e1e4-f23bd1550000}
        ProcessId      : 6559
        User           : root
        Image          : /usr/bin/rm
        TargetFilename : /var/log/app_audit.log
        Hashes         : -
        IsExecutable   : -
        Archived       : -

    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # ProcessGuid to search for, one or more can be provided.
        [Parameter(Mandatory=$false,
            ParameterSetName="ProcessGuid")]
        [string[]]
        $ProcessGuid,

        # RuleName to search for, one or more can be provided.
        #[Parameter(mandatory=$false)]
        #[string[]]
        #$RuleName,

        # ProcessID to search for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ProcessId,

        # Image to search for, one or more can be provided. The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $Image,

        # TargetFilename to search for, one or more can be provided. The '*' wildcard is supported for matching.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $TargetFilename,

        # User to seach for, one or more can be provided.
        [Parameter(Mandatory=$false)]
        [string[]]
        $User,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {
  
        $pattern = "^*sysmon:.*<EventID>23<\/EventID>"

        if ($RuleName.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"RuleName`">($($RuleName))<\/Data>"
        }


        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"ProcessGuid`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"(ProcessId)`">($($ProcessId -join "|"))<\/Data>"
        }

        if ($Image.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Image`">($(($Image -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($TargetFilename.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"TargetFilename`">($(($TargetFilename -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "FileDelete"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.FileDelete"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxRawAccess {
    <#
    .SYNOPSIS
        Gets Sysmon events for direct access to a block device.
    .DESCRIPTION
        Gets Sysmon events for direct access to a block device. from Syslog logs.It allows filtering by field content.
    .EXAMPLE
        PS /> Get-SysmonLinuxRawAccess | select image,device,user -unique | ConvertTo-SysmonRule
        <Rule groupRelation="and">
        <Image condition='is'>/usr/lib/systemd/systemd-logind</Image>
        <Device condition='is'>/dev/sda1</Device>
        <User condition='is'>root</User>
        </Rule>
        <Rule groupRelation="and">
        <Image condition='is'>/usr/lib/systemd/systemd-logind</Image>
        <Device condition='is'>/dev/sda</Device>
        <User condition='is'>root</User>
        </Rule>
        <Rule groupRelation="and">
        <Image condition='is'>/usr/sbin/dumpe2fs</Image>
        <Device condition='is'>/dev/sda5</Device>
        <User condition='is'>root</User>
        </Rule>
        <Rule groupRelation="and">
        <Image condition='is'>/usr/sbin/blkid</Image>
        <Device condition='is'>/dev/sda5</Device>
        <User condition='is'>root</User>
        </Rule>
        <Rule groupRelation="and">
        <Image condition='is'>/usr/sbin/blkid</Image>
        <Device condition='is'>/dev/sda</Device>
        <User condition='is'>root</User>
        </Rule>
        <Rule groupRelation="and">
        <Image condition='is'>/usr/sbin/grub-probe</Image>
        <Device condition='is'>/dev/sda</Device>
        <User condition='is'>root</User>
        </Rule>

        Create rule set for use in exclusion of known behaviour.
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # ProcessGuid to search for a given event type.
        [Parameter(Mandatory=$false,
            ParameterSetName="ProcessGuid")]
        [string[]]
        $ProcessGuid,

        # RuleName to search for the given event type.
        #[Parameter(mandatory=$false)]
        #[string[]]
        #$RuleName,

        # ProcessID to search for a given event type.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ProcessId,

        # Image to search for a given event type.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $Image,

        # TargetFilename to search for a given event type.
        [Parameter(mandatory=$false)]
        [string]
        $Device,

        # User to seach for a given event type.
        [Parameter(Mandatory=$false)]
        [string[]]
        $User,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {
  
        $pattern = "^*sysmon:.*<EventID>9<\/EventID>"

        if ($RuleName.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"RuleName`">($($RuleName))<\/Data>"
        }


        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"ProcessGuid`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"(ProcessId)`">($($ProcessId -join "|"))<\/Data>"
        }

        if ($Image.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Image`">($(($Image -join "|").Replace("`*","\S`*")))<\/Data>"
        }

        if ($Device.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Device`">($($Device))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "FileDelete"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.FileDelete"
            $Obj
        }
    }
    
    end {
        
    }
}

function Get-SysmonLinuxNetworkConnect {
    <#
    SYNOPSIS
        Gets Sysmon network events from Syslog logs.
    .DESCRIPTION
        Gets Sysmon network events from Syslog logs.It allows filtering by field content.
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        System.IO.FileInfo
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        General notes
    #>
    [CmdletBinding(DefaultParameterSetName="All")]
    param (

        # Specifies a path to one or more locations.
        [Parameter(
                   Position=0,
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true,
                   HelpMessage="Path to one or more locations.")]
        [Alias("PSPath")]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_})]
        [string[]]
        $SyslogFile = @("/var/log/syslog"),

        # ProcessGuid to search for a given event type.
        [Parameter(Mandatory=$false,
            ParameterSetName="ProcessGuid")]
        [string[]]
        $ProcessGuid,

        # RuleName to search for the given event type.
        #[Parameter(mandatory=$false)]
        #[string[]]
        #$RuleName,

        # ProcessID to search for a given event type.
        [Parameter(Mandatory=$false)]
        [string[]]
        $ProcessId,

        # Image to search for a given event type.
        [Parameter(mandatory=$false)]
        [SupportsWildcards()]
        [string[]]
        $Image,

        # User to seach for a given event type.
        [Parameter(Mandatory=$false)]
        [string[]]
        $User,

        # User to seach for a given event type.
        [Parameter(Mandatory=$false)]
        [ValidateSet('TCP','UDP')]
        [string]
        $Protocol,

        # User to seach for a given event type.
        [Parameter(Mandatory=$false)]
        [ValidateSet('True','False')]
        [string]
        $Initiated,

        [Parameter(Mandatory=$false)]
        [ValidateSet('True','False')]
        [string]
        $SourceIsIpv6,

        [Parameter(Mandatory=$false)]
        [string[]]
        $SourceIp,

        [Parameter(Mandatory=$false)]
        [string[]]
        $SourcePort,

        [Parameter(Mandatory=$false)]
        [ValidateSet('True','False')]
        [string]
        $DestinationIsIpv6,

        [Parameter(Mandatory=$false)]
        [string[]]
        $DestinationIp,

        [Parameter(Mandatory=$false)]
        [string[]]
        $DestinationPort,

        # Start Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $StartTime,

        # End Time to search for event created on and after this time. 
        [Parameter(Mandatory=$false)]
        [datetime]
        $EndTime

    )
    
    begin {
  
        $pattern = "^*sysmon:.*<EventID>3<\/EventID>"

        if ($RuleName.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"RuleName`">($($RuleName))<\/Data>"
        }


        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"ProcessGuid`">($($ProcessGuid -join "|"))<\/Data>"
        }

        if ($ProcessGuid.Length -gt 0){
            $pattern = $pattern + ".*<Data Name=`"(ProcessId)`">($($ProcessId -join "|"))<\/Data>"
        }

        if ($Image.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Image`">($($Image.Replace("`*","\S`*")))<\/Data>"
        }

        if ($Protocol.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Protocol`">($(($Protocol -join "|").ToLower()))<\/Data>"
        }

        if ($Initiated.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"Initiated`">($(($Initiated -join "|").ToLower()))<\/Data>"
        }

        if ($SourceIsIpv6.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"SourceIsIpv6`">($(($SourceIsIpv6 -join "|").ToLower()))<\/Data>"
        }

        if ($SourceIp.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"SourceIp`">($(($SourceIp -join "|")))<\/Data>"
        }

        if ($SourcePort.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"SourcePort`">($(($SourcePort -join "|")))<\/Data>"
        }

        if ($DestinationIsIpv6.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"DestinationIsIpv6`">($(($DestinationIsIpv6 -join "|").ToLower()))<\/Data>"
        }

        if ($DestinationIp.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"DestinationIp`">($(($DestinationIp -join "|")))<\/Data>"
        }

        if ($DestinationPort.Length -gt 0) {
            $pattern = $pattern + ".*<Data Name=`"DestinationPort`">($(($DestinationPort -join "|")))<\/Data>"
        }

        write-verbose -Message "RegEx is $pattern"

        $ParamsPassed = $PSBoundParameters.Keys
    }
    
    process {
        if ($SyslogFile -like "*.gz") {
            $file2process = Expand-GzFile (resolve-path $SyslogFile).Path
        } else {
            $file2process = $SyslogFile
        }
        Write-Verbose -Message "Opening $($file2process)"
        Select-String -Pattern $pattern -Path $file2process | ForEach-Object {
            try {
                $evtxml = [xml]($_.line.split("sysmon:"))[1]
            } catch {
                return
            }
            $EvtInfo = [ordered]@{}
            $EvtInfo['EventId'] = $evtxml.Event.System.EventID
            $EvtInfo['Version'] = $evtxml.Event.System.Version
            $EvtInfo['EventType'] = "NetworkConnect"
            $EvtInfo['Computer'] = $evtxml.Event.System.Computer
            $EvtInfo['EventRecordID'] = $evtxml.Event.System.EventRecordID
            $evtxml.event.eventdata.data | ForEach-Object {
                $EvtInfo[$_.name] = $_.'#text'
            }
            if ($ParamsPassed -contains "StartTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -ge $StartTime)) { return }
            }

            if ($ParamsPassed -contains "EndTime") {
                if (!([datetime]$EvtInfo['UtcTime'] -le $EndTime)) { return }
            }
            $Obj = New-Object psobject -Property $EvtInfo
            $Obj.pstypenames[0] = "Sysmon.EventRecord.NetworkConnect"
            $Obj
        }
    }
    
    end {
        
    }
}

function ConvertTo-SysmonRule {
    <#
    .SYNOPSIS
        Turn Sysmon Event objects in to Rules or RuleGroups for use in configuration files.
    .DESCRIPTION
        Funtion for creationg Rules or RuleGroups depending on the number of properties from Sysmon Event Objects. When more than
        1 property select will be turned in to RuleGroups, if only one property is present they are turned in to Rules. RuleGroups
        have a Group Relation of 'and'. For rules since exact matches are used the conditions supported for selectio are 'is', 
        'is not', "excludes",  "begin with" and "image". Default consition if not specified the "is" is used.
    .EXAMPLE
        
    .INPUTS
        System.Management.Automation.PSCustomObject
        System.String
    .OUTPUTS
        System.String
    .NOTES
        General notes
    #>
    [CmdletBinding()]
    param (
        # Sysmon Event Object
        [Parameter(Mandatory = $true,
        ValueFromPipeline = $true)]
        [pscustomobject[]]
        $SysmonEvent,

        # Rule condition.
        [Parameter(Mandatory=$false)]
        [ValidateSet('is', 'is not',"excludes", "begin with","image")]
        [string]
        $Condition = "is"
    )
    
    begin {
        
    }
    process {

        foreach($event in $SysmonEvent) {
            $propCount = (Get-Member -InputObject $event -MemberType Properties).count
            if ($propCount -eq 1){
                $event.PSObject.Properties | ForEach-Object {
                    "<$($_.name) condition='$($Condition)'>$($_.value.Replace("&","&amp;"))</$($_.name)>"
                }

            } elseif ($propCount -gt 1) {
                $RuleGroup = "<Rule groupRelation=`"and`">`n"
                $event.PSObject.Properties | ForEach-Object {
                    $RuleGroup += "  <$($_.name) condition='$($Condition)'>$($_.value.Replace("&","&amp;"))</$($_.name)>`n"
                }
                $RuleGroup += "</Rule>"
                $RuleGroup
            }
        }
    }
    end {}
}


Function Expand-GzFile{                         
    Param(
        $infile
    ) 
    begin{}

    process{
        $outfile = "$([System.IO.Path]::GetTempPath())$([System.IO.Path]::GetFileNameWithoutExtension($infile))"
        $inputfile = New-Object System.IO.FileStream $inFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
        $output = New-Object System.IO.FileStream $outFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
        $gzipStream = New-Object System.IO.Compression.GzipStream $inputfile, ([IO.Compression.CompressionMode]::Decompress)
        
        $buffer = New-Object byte[](1024)
        while($true){
        $read = $gzipstream.Read($buffer, 0, 1024)
        if ($read -le 0){break}
            $output.Write($buffer, 0, $read)
        }
        
        $gzipStream.Close()
        $output.Close()
        $inputfile.Close()

        $outfile
    }   
}

