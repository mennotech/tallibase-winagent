#Example how to use this modules
Import-Module -Name (Join-Path "." "modules" "MTLogger.psm1") -Force
Import-Module -Name (Join-Path "." "modules" "Tallibase.psm1") -Force

# Connect and save credentials

# Connect-Tallibase -Server "localhost" -NoSSL -AuthString "user:test" -SaveAuth -LogLevel 4

# Connect with saved credentials
Connect-Tallibase -Server "localhost" -NoSSL