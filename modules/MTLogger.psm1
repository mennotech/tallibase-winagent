
#Set default log level
$Script:LogLevel = 4
$Script:LogFile = $null


<# 
.COMPONENT
    Write-MTLog

.SYNOPSIS
    Logs messages to the log file and console with different severity levels.

.PARAMETER
    Message
        The message to log.

.PARAMETER
    Level
        The severity level of the message. Valid values are:
        1 - FATAL: Critical errors that cause the application to shut down.
        2 - ERROR: Non-critical errors that do not cause shutdown but indicate a problem.
        3 - WARNING: Potential issues that should be noted but do not require immediate action.
        4 - INFO: General information messages that are useful for understanding the flow of the application.
        5 - DEBUG: Detailed debugging information, useful for developers.
        6 - TRACE: Very detailed tracing information, useful for in-depth debugging.

#>
function Write-MTLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [Parameter(Mandatory = $false)]
        [ValidateSet(1,2,3,4,5,6)]
        [int]$Level = 4
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $Message = "($timestamp) $Message"


    switch($Level) {
        1 { $logMessage = "[FATAL] $Message"; $color = "Red" }
        2 { $logMessage = "[ERROR] $Message"; $color = "Red" }
        3 { $logMessage = "[WARNING] $Message"; $color = "Yellow" }
        4 { $logMessage = "[INFO] $Message"; $color = "Green" }
        5 { 
            # Get calling function name and line number
            2..3 | ForEach-Object { 
                if ($caller = (Get-PSCallStack)[$_]) { 
                    $callerInfo =  "$callerInfo/$($caller.FunctionName):$($caller.ScriptLineNumber)" 
                }
            }
            $logMessage = "[DEBUG] $Message @{$($callerInfo)}"; $color = "Cyan" }
        6 { 
            # Get calling function name and line number
            2..5 | ForEach-Object { 
                if ($caller = (Get-PSCallStack)[$_]) { 
                    $callerInfo =  "$callerInfo/$($caller.FunctionName):$($caller.ScriptLineNumber)" 
                }
            }
            $logMessage = "[TRACE] $Message @{$($callerInfo)}"; $color = "Magenta" 
        }
    }

    if ($script:LogLevel) {
        if ($Level -le $script:LogLevel) {
            # Write to console
            Write-Host $logMessage -ForegroundColor $color            
        }
        if ($script:logFile -and ($Level -le 4 -or $Level -le $script:LogLevel)) {
            # Write to log file
            try {
                Add-Content -Path $script:logFile -Value $logMessage -ErrorAction Stop
            } catch {
                Write-Host "[FATAL] Failed to write to log file: $_" -ForegroundColor Red
                throw
            }            
        }
    } else {
        # Write to console
        Write-Host $logMessage -ForegroundColor $color
    }
}
Export-ModuleMember -Function Write-MTLog

function Set-MTLogLevel {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(1,2,3,4,5,6)]
        [int]$Level
    )
    
    $script:LogLevel = $Level
    Write-MTLog -Message "Log level set to $Level" -Level 4
}
Export-ModuleMember -Function Set-MTLogLevel

function Set-MTLogFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )
    
    if (-not (Test-Path -Path $FilePath)) {
        New-Item -Path $FilePath -ItemType File -Force | Out-Null
    }
    
    $script:LogFile = $FilePath
    Write-MTLog -Message "Log file set to $FilePath" -Level 4
}