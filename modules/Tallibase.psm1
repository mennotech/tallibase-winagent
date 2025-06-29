<#
  Common functions used by scripts
#>

#Requires -Version 5.1
#Requires -Module MTLogger


function Read-TallibaseConfig {
    param(
        [string]$Path = ".\settings.json"
    )
    
    #Load settings, TODO validate JSON for required configuration fields
    try { 
        $script:settings = Get-Content $Path | ConvertFrom-JSON 
    }
    catch {
        Write-MTLog -Level 1 -Message "Failed to load $Path make sure it is a valid JSON file. Exiting"
        return 1
    }
    if (!$script:settings) {
        Write-MTLog -Level 1 -Message "Failed to load JSON settings from $Path, please rename Settings.Example.json to Settings.json "
        return 1
    }

    #Parse settings and apply to variables
    $script:SiteURL = $script:settings.server
    if ($script:settings.loglevel) { $script:loglevel = $script:settings.loglevel}

    #Exit if password file doesn't exist
    if (!(Test-Path -Path "$PSScriptRoot\$($script:settings.encryptedpasswordfile)" )) {
        Write-MTLog -Level 1 -Message  "Failed to find password file $PSScriptRoot\$($script:settings.encryptedpasswordfile)"
        Write-MTLog -Level 1 -Message  "Please run Save-Password.ps1 to create"
        return 2
    }

    #Read encrypted password
    $Username,$Password = Get-Content "$PSScriptRoot\$($script:settings.encryptedpasswordfile)"
    if (!($Username -AND $Password)) {
        Write-MTLog -Level 1 -Message "Failed to load username and password"
        return 3
    }

    #Create Authentication Headers
    $Password = $Password | ConvertTo-SecureString
    $Pair = "$($Username):$([System.Net.NetworkCredential]::new('', $Password).Password)"
    $EncodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
    $script:headers = @{ Authorization = "Basic $EncodedCreds"; 'Content-Type' = "application/json" };
}
Export-ModuleMember -Function Read-TallibaseConfig

function Invoke-DrupalResource {
    Param(
        $Path,
        $Method = "GET",
        $Simplify = $true,
        $RAWBody = $false,
        $Headers = $script:headers,
        $Body = $null
    )

    if ($Body -and ! $RAWBody) {
        try {
            $Body = ConvertTo-DrupalResource -Object $Body
            $Body = ConvertTo-Json -Compress -Depth 5 -InputObject $Body
            Write-MTLog -Level 8 -Message "POST body: $body"
        }
        catch {
            Write-MTLog -Level 3 -Message "Get-DrupalResource: Failed to convert Body to JSON. Data: $Body"
            return $false
        }
    }

    #TODO write a caching function for calls to the same path

    Write-MTLog -Level 6 -Message "HTTP $Method $($script:SiteURL)/$Path`?_format=json"    
        
    $Resource = Invoke-RestMethod `
        -Uri "$($script:SiteURL)/$Path`?_format=json" `
        -Headers $headers `
        -Method $Method `
        -Body $Body
    
    if ($Simplify) {
        return Get-SimplifiedDrupalObject $Resource
    } else {
        return $Resource
    }
}
Export-ModuleMember -Function Invoke-DrupalResource

function ConvertTo-DrupalResource {
    param(
        $Object
    )
    
    foreach ($property in $Object.PsObject.Properties) {        
        if ($property.name -ne 'type' -AND $property.value -isnot [System.Management.Automation.PSCustomObject]) {
            $Object.PsObject.Properties.Remove($property.name)
            $Object | Add-Member -MemberType NoteProperty `
                -Name $property.name `
                -Value @([PSCustomObject]@{ "value" = $property.value })
        }
    }
    return $Object
}

function Get-SimplifiedDrupalObject {
    param(
        [Parameter(ValueFromPipelineByPropertyName)]$Objects
    )
    process {
        foreach ($Object in $Objects) {
            foreach ($property in $Object.PsObject.Properties) {
                if ($null -ne $property.Value.value) {
                    $property.Value =  @($property.Value.value)
                }
            }
        }
        return $Objects
    }
}
Export-ModuleMember -Function Get-SimplifiedDrupalObject


function Update-TallibaseDevices {
    Param(
        $Devices
    )
    
    Write-MTLog -Level 6 -Message "Updating Tallibase Database..."
    
    $WebDevices = Invoke-DrupalResource -Path "views/devices"

    foreach ($Device in $Devices) {
        if ($Device.SerialNumber -in $WebDevices.field_serial_number) {
            $WebDevice = $WebDevices | Where-Object field_serial_number -eq $Devices.SerialNumber
            if (($WebDevice).count -eq 1) {
                $null = Update-TallibaseDevice -AssetInfo $Device -UUID $WebDevice
            }
        } else {
            $null = New-TallibaseDevice -AssetInfo $Device
        }
    }

}
Export-ModuleMember -Function Update-TallibaseDevice

function Get-TallibaseFieldOptions {
    Param(
        $Vendors = $true,
        $DeviceModels = $true
    )
    if ($Vendors -and !$script:TallibaseVendors) { 
        [array]$script:TallibaseVendors = Invoke-DrupalResource -Path "vendor" 
    }
    
    if ($DeviceModels -and !$script:TallibaseDeviceModels) {
        [array]$script:TallibaseDeviceModels = Invoke-DrupalResource -Path "device_model"
    }
}
Export-ModuleMember -Function Get-TallibaseFieldOptions

function New-TallibaseDevice {
    Param(
        $AssetInfo = $null
    )
    
    #Load field options if needed
    Get-TallibaseFieldOptions
    
    if ($AssetInfo) {
        Write-MTLog -Level 6 -Message "Creating new TalliBase device $AssetInfo"
        
        $TalliBaseResource = [PSCustomObject]@{
            type = "device"
            title = $AssetInfo.DeviceName
            field_device_model = Get-TalliBaseFieldID -FieldName 'field_device_model' -Value $AssetInfo.Model
            field_serial_number = $AssetInfo.SerialNumber
            field_manufacturer = Get-TalliBaseFieldID -FieldName 'field_manufacturer' -Value $AssetInfo.Manufacturer
        }
        
        return Invoke-DrupalResource -Path "node" -Method "POST" -Body $TalliBaseResource
    }

}
Export-ModuleMember -Function Get-TallibaseDevice

function Get-TalliBaseFieldID {
    Param(
        [string]$FieldName = (raise "Provided a FieldName"),
        $Value = (raise "Provided a Value")
    )
    #TODO fix this to make it more dynamic
    Get-TallibaseFieldOptions
    switch ($FieldName) {
        "field_device_model" {
            if ($Value -in $script:TallibaseDeviceModels.title) {
                return [PSCustomObject]@{
                    target_id = [string]($script:TallibaseDeviceModels | Where-Object title -eq $Value).nid
                }
            }
            else {
                Write-MTLog -Level 6 -Message "Did not find $FieldName with value $Value, creating"
                $TalliBaseResource = [PSCustomObject]@{
                    type = "device_model"
                    title = $Value
                }
                $NewResource = Invoke-DrupalResource -Path "node" -Method "POST" -Body $TalliBaseResource
                #Update vendors
                if ($NewResource) {
                    $script:TallibaseDeviceModels += $NewResource
                    return [PSCustomObject]@{
                        target_id = [string]$NewResource.nid
                    }
                } else {
                    return $false
                }
            }
        }
        "field_manufacturer" {
            if ($Value -in $script:TallibaseVendors.title) {
                return [PSCustomObject]@{
                    target_id = [string]($script:TallibaseVendors | Where-Object title -eq $Value).nid
                }
            }
            else {
                Write-MTLog -Level 6 -Message "Did not find $FieldName with value $Value, creating"
                $TalliBaseResource = [PSCustomObject]@{
                    type = "vendor"
                    title = $Value
                }
                $NewResource = Invoke-DrupalResource -Path "node" -Method "POST" -Body $TalliBaseResource
                #Update vendors
                if ($NewResource) {
                    $script:TallibaseVendors += $NewResource
                    return [PSCustomObject]@{
                        target_id = [string]$NewResource.nid
                    }
                } else {
                    return $false
                }
            }
        }
    }

}
Export-ModuleMember -Function Get-TalliBaseFieldID

function Set-TallibaseServer {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Server
    )

    # Set the server URL in the script scope
    $script:SiteURL = $Server

    # Write a log message indicating the server has been set
    Write-MTLog -Level 5 -Message "Tallibase server set to: $Server"
}
Export-ModuleMember -Function Set-TallibaseServer

function Set-LogLevel {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(1,2,3,4,5,6)]
        [int]$LogLevel
    )

    # Set the log level in the script scope
    $script:LogLevel = $LogLevel

    # Write a log message indicating the log level has been set
    Write-MTLog -Level 6 -Message "Log level set to: $LogLevel"
}
Export-ModuleMember -Function Set-LogLevel

function Set-TallibaseHeader {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Header
    )

    
    # Initialize the headers if not already done
    if (-not $script:headers) {
        $script:headers = $Header
    } else {
        # Check if the header already exists
        if ($script:headers.ContainsKey($Header.Keys)) {
            Write-MTLog -Level 3 -Message "Header $($Header.Keys) already exists, updating value."
            foreach ($key in $Header.Keys) {
                # Update the existing header value
                $script:headers[$key] = $Header[$key]
            }
        } else {
            Write-MTLog -Level 5 -Message "Adding new header: $($Header.Keys)"
            # Add the new header to the script scope headers
            foreach ($key in $Header.Keys) {
                $script:headers[$key] = $Header[$key]
            }
        }

    }

    # Write a log message indicating the header has been added
    Write-MTLog -Level 6 -Message "Header added: $($Header.Keys)"
}
Export-ModuleMember -Function Set-TallibaseHeader

function Get-TallibaseHeaders {
    # Return the current headers
    return $script:headers
}
Export-ModuleMember -Function Get-TallibaseHeaders


<#
.COMPONENT
    Connect-Tallibase

.SYNOPSIS
    The script will test the connection to the Tallibase server and authenticate using the specified method.
    If the connection is successful, it will log the success and optionally save the credentials to a file.

.PARAMETER
    Server
        The hostname of the Tallibase server to connect to (e.g. one.tallibase.io).

.PARAMETER
    AuthMethod
        The authentication method to use. Valid values are BASIC, DIGEST, OAUTH2, JWT. Default is BASIC.

.PARAMETER
    IgnoreCertificate  
        Ignore SSL certificate errors. This is useful for self-signed certificates or development environments.

.PARAMETER
    NoSSL
        Disable SSL. This should only be used for localhost or development environments.

.PARAMETER
    AuthString
        The connection string to use if no cached credentials are available. Format: 'username:password'.
        This is required if no cached credentials are found.

.PARAMETER
    LogLevel
        The level of logging to use. Valid values are 1-FATAL, 2-ERROR, 3-WARNING, 4-INFO, 5-DEBUG, 6-TRACE. Default is 4.

.PARAMETER
    SaveCredentials
        If specified, the script will save the credentials to a file for future use. This is useful for avoiding repeated authentication.

#>
function Connect-Tallibase {

    param(
    [Parameter(Mandatory = $false)]
    [string]$Server,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("BASIC", "DIGEST", "OAUTH2", "JWT")]
    [string]$AuthMethod = "BASIC",
    
    [Parameter(Mandatory = $false)]
    [switch]$IgnoreCertificate = $false,
    
    [Parameter(Mandatory = $false)]    
    [switch]$NoSSL = $false,

    [Parameter(Mandatory = $false)]
    [string]$AuthString = $null,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet(1,2,3,4,5,6)]
    [int]$LogLevel,

    [Parameter(Mandatory = $false)]
    [switch]$SaveAuth = $false,

    [Parameter(Mandatory = $false)]
    [switch]$Help = $false
)


# Write the usage information
function Show-Usage {
    Write-Host "`nUsage: Connect-Tallibase.ps1 -Server <ServerName> [-AuthMethod <AuthMethod>] [-ConnectionString <ConnectionString>] [-LogLevel <LogLevel>]"
    Write-Host "Parameters:"
    Write-Host "  -Server             The hostname of the Tallibase server to connect to (e.g. one.tallibase.io)."
    Write-Host "  -AuthMethod         The authentication method to use (default is 'SIMPLE')."
    Write-Host "  -AuthString         The connection string to use if no cached credentials are available."
    Write-Host "  -SaveAuth           If specified, the script will save the credentials to a file for future use."
    Write-Host "  -LogLevel           The level of logging to use (default is 4). Valid values are 1-FATAL, 2-ERROR, 3-WARNING, 4-INFO, 5-DEBUG, 6-TRACE."
    Write-Host "  -IgnoreCertificate  Ignore SSL certificate errors."
    Write-Host "  -NoSSL              Disable SSL (should only be used for localhost)."
    
    Write-Host "`nExample: Connect-Tallibase.ps1 -Server 'myserver' -AuthMethod 'SIMPLE' -ConnectionString 'Data Source=myserver;Initial Catalog=mydb;User ID=myuser;Password=mypassword;'"
    Write-Host "`nIf you need help, please refer to the documentation at https://github.com/mennotech/tallibase-winagent"
    return
}

if ($Help) { Show-Usage; return}

if ($LogLevel) {
    # Set the log level in the script scope
    Set-LogLevel -LogLevel $LogLevel
}


function Main {

    # Test connection to the Tallibase server using the provided credentials
    try {
        $node = Invoke-DrupalResource -Path 'node/1'
        if (-not $node) {
            Write-MTLog -Level 1 -Message "Failed to authenticate with BASIC credentials."
            return
        }               
    } catch {
        Write-MTLog -Level 1 -Message "Error connecting to the Tallibase server: $_"
        return
    }

    Write-MTLog -Level 4 -Message "Connection to Tallibase server: $Server established successfully."

    if ($SaveAuth) {
        Write-MTLog -Level 4 -Message "Saving credentials to $global:cachedCredentialsFilePath"
        # Save the credentials to Windows Credential Manager
        try {
            $script:Credential | Export-CliXml -Path $global:cachedCredentialsFilePath -ErrorAction Stop
            Write-MTLog -Level 5 -Message "Cached credentials for server: $Server to file: $global:cachedCredentialsFilePath"
        } catch {
            Write-MTLog -Level 1 -Message "Failed to cache credentials to file: $global:cachedCredentialsFilePath. Error: $_"
            return
        }
    }
    
}

# Initialize the script
# This function sets up the environment, validates parameters, and prepares for the connection.
function Init {
    
    # Process Server and Port parameters

    # If Server is not provided, use the environment variable
    if (-not $Server) {
        if ($env:TALLIBASE_SERVER) {
            $Server = $env:TALLIBASE_SERVER
            Write-MTLog -Level 4 -Message "Using TALLIBASE_SERVER environment variable: $Server"
        } else {
            Write-MTLog -Level 1 -Message "No server specified and TALLIBASE_SERVER environment variable is not set."
            throw
        }
    }

    # Validate the Server parameter
    if (-not $Server -or $Server -eq "") {
        Write-MTLog -Level 1 -Message "Server parameter is required and cannot be empty."
        Show-Usage
        throw
    }

    # Check if the Server parameter is a valid hostname
    if ($Server -notmatch '^[a-zA-Z0-9][a-zA-Z0-9.-:]*$') {
        Write-MTLog -Level 1 -Message "Invalid server name format: $Server. It must be a valid hostname."
        Show-Usage
        throw
    }

    # Split the hostname into parts and validate the port
    ($hostname,$port) = $Server -split '[:]'
    if (-not $port) {
        if ($hostname -eq 'localhost') {
            $port = 8080  # Default to port 8080 for localhost if not specified
            Write-MTLog -Level 5 -Message "Using default port 8080 for localhost."
        } else {
            Write-MTLog -Level 5 -Message "No port specified, using default port 443."
            # Default to port 443 for other servers
            $port = 443  # Default port if not specified
        }        
    } else {
        try {
            $port = [int]$port  # Convert port to integer
        } catch {
            Write-MTLog -Level 1 -Message "Invalid port number: $port. It must be a valid integer."
            Show-Usage
            return
        }
    }

    # Set connection protocol based on NoSSL switch
    if ($NoSSL) {
        Write-MTLog -Level 5 -Message "NoSSL switch is enabled. Using HTTP protocol."
        $protocol = "http"
    } else {
        Write-MTLog -Level 5 -Message "NoSSL switch is not enabled. Using HTTPS protocol."
        $protocol = "https"
    }

    # Test connection to the server
    try {
        Write-MTLog -Level 4 -Message "Testing connection to server: $Server on port $port."
        $tcpConnection = Test-Connection -IPv4 -ComputerName $hostname -TcpPort $port -WarningAction SilentlyContinue
        if (-not $tcpConnection) {
            Write-MTLog -Level 1 -Message "Failed to connect to server: $Server on port $port."
            return
        } else {
            Write-MTLog -Level 5 -Message "Successfully connected to server: $Server on port $port."
        }
    } catch {
        Write-MTLog -Level 1 -Message "Error testing connection to server: $_"
        return
    }

    # Set script:$SiteURL
    Set-TallibaseServer -Server "$($protocol)://$($hostname):$port"


    # Set the path for cached credentials
    $global:cachedCredentialsFilePath = Join-Path "." ".tallibaseredential_$($AuthMethod)_$($protocol)_$($hostname)_$($port).xml"

    # If Credentials are not provided, check for cached credentials
    if (-not $AuthString) {

        # Check if the cached credentials file exists
        if (Test-Path -Path $global:cachedCredentialsFilePath) {
            try {
                $Credential = Import-CliXml -Path $global:cachedCredentialsFilePath -ErrorAction Stop
                Write-MTLog -Level 5 -Message "Cached credentials found for server: $Server"
                $Username = $Credential.UserName
                $Password = $Credential.GetNetworkCredential().Password
                Write-MTLog -Level 5 -Message "Cached usersname: $Username"
                
                #Create Encoded credentials for BASIC authentication                
                $Pair = "$($Username):$Password"
                $EncodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
                $Username = $null
                $Password = $null
            } catch {
                Write-MTLog -Level 1 -Message "Failed to import cached credentials from file: $cachedCredentialsFilePath. Error: $_"
                throw
            }
        } else {
            Write-MTLog -Level 2 -Message "No cached credentials found for server: $Server"
            Write-MTLog -Level 2 -Message "You will need to provide credentials to connect to the server."
            Write-MTLog -Level 2 -Message "Please provide the credentials using the -AuthString parameter in the format 'username:password'"
            return
        }

    } else {
        Write-MTLog -Level 4 -Message "Using provided credentials for server: $Server"
        # Convert the SecureString credentials to a plain text string
        switch ($AuthMethod) {
            "BASIC" {
                ($Username, $Password) = $AuthString -split ':'
                if (-not $Username -or -not $Password) {
                    Write-MTLog -Level 1 -Message "Invalid BASIC authentication string format. Expected format: 'username:password'"
                    Show-Usage
                    return
                }                
                $script:Credential = New-Object System.Management.Automation.PSCredential ($Username, (ConvertTo-SecureString -String $Password -AsPlainText -Force))
                #Create Encoded credentials for BASIC authentication
                $Pair = "$($Username):$([System.Net.NetworkCredential]::new('', $Password).Password)"
                $EncodedCreds = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair))
                
            }
            "DIGEST" { 
                $Credential = ConvertTo-SecureString -String $AuthString -AsPlainText -Force
            }
            "OAUTH2" {
                $Credential = ConvertTo-SecureString -String $AuthString -AsPlainText -Force
            }
            "JWT" {
                $Credential = ConvertTo-SecureString -String $AuthString -AsPlainText -Force
            }
            default {
                Write-MTLog -Level 1 -Message "Invalid authentication method: $AuthMethod. Valid methods are BASIC, DIGEST, OAUTH2, JWT."
                Show-Usage
                return
            }
        }
        # Clear the $AuthString variable to avoid accidental reuse
        $AuthString = $null
        $Username = $null
        $Password = $null
    }

    # Validate the Credential object
    if (-not $Credential) {
        Write-MTLog -Level 1 -Message "No valid credentials provided or cached for server: $Server."
        Show-Usage
        return
    }


    # Set authentication headers
    switch($AuthMethod) {
        "BASIC" {                
            Set-TallibaseHeader -Header @{'Authorization' = "Basic $EncodedCreds";}
        }
        "DIGEST" { Write-MTLog -Level 4 -Message "DIGEST method not yet supported." return }
        "OAUTH2" { Write-MTLog -Level 4 -Message "OAUTH2 method not yet supported."; return }            
        "JWT" { Write-MTLog -Level 4 -Message "JWT method not yet supported."; return }
        default {
            Write-MTLog -Level 1 -Message "Invalid authentication method: $AuthMethod. Valid methods are BASIC, DIGEST, OAUTH2, JWT."
            Show-Usage
            return
        }
    }

}







    try {
        # Execute the main function
        Init
        Main
        
    } catch {
        # Write error including error line number
        Write-MTLog -Level 2 -Message "An error occurred in the script: $_"
        Write-MTLog -Level 2 -Message "Script Name: $($_.InvocationInfo.ScriptName)"    
        Write-MTLog -Level 2 -Message "Fully Qualified Error ID: $($_.FullyQualifiedErrorId)"        
        Write-MTLog -Level 2 -Message "Line: $($_.InvocationInfo.ScriptLineNumber):$($_.InvocationInfo.OffsetInLine)"
        Write-MTLog -Level 2 -Message "Category: $($_.CategoryInfo.Category)"
    }
}
Export-ModuleMember -Function Connect-Tallibase