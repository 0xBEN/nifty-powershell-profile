#####################
##### Functions #####
#####################

function Redo-ModuleImport {

    [CmdletBinding()]
    [Alias("reload")]
    param()
    DynamicParam {  

        # Create a dictionary to hold any dynamic parameters
        $parameterDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary 

        #########################################   
        #### Dynamic Parameter 1: ModuleName ####
        #########################################
        $moduleNameParameterName = 'ModuleName'
        
	# Parameter Attributes
        $moduleNameParameterAttributes = New-Object System.Management.Automation.ParameterAttribute # Instantiate empty parameter attributes object for definition below
        $moduleNameParameterAttributesCollection = New-Object 'System.Collections.ObjectModel.Collection[System.Attribute]' # An array to hold any attributes assigned to this parameter
        $moduleNameParameterAttributes.Mandatory = $true # Parameter is mandatory
        $moduleNameParameterAttributes.Position = 0
        
	# Parameter should validate inputs on these constraints
        $moduleNameParameterValidationSet = (Get-Module -All).Name # Get a list of all loaded modules as the set of strings that can be passed in by the user
        $moduleNameParameterValidationSetAttribute = New-Object System.Management.Automation.ValidateSetAttribute($moduleNameParameterValidationSet)
        
	# Add the parameter attributes object and the validation set attribute
        $moduleNameParameterAttributesCollection.Add($moduleNameParameterAttributes)
        $moduleNameParameterAttributesCollection.Add($moduleNameParameterValidationSetAttribute)
        $createModuleNameParameter = New-Object System.Management.Automation.RuntimeDefinedParameter($moduleNameParameterName, [String[]], $moduleNameParameterAttributesCollection)
        
        $parameterDictionary.Add($moduleNameParameterName, $createModuleNameParameter) # Add ModuleName to the parameter dictionary
        return $parameterDictionary

    }
    process{

        $PSBoundParameters['ModuleName'] | ForEach-Object {
            try {
                $module = Get-Module -All -Name $_
                $module | Remove-Module -Force -ErrorAction Stop
                Import-Module $module.Path -Force -ErrorAction Stop
            }
            catch {
                Write-Error -Exception $_.Exception
            }
        }

    }
    
}

function touch {
    
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Path
    )
    process {
    
        try {
            $defaultEA = $ErrorAction
            $ErrorAction = 'Stop'
            $isNixStyle = which touch
        }
        catch {
            $isNixStyle = $false
        }
        $ErrorAction = $defaultEA

        if ($isNixStyle) {

            $Path | ForEach-Object {
                Start-Process -FilePath $isNixStyle -ArgumentList $_ -ErrorAction Continue
            }
            return
            
        }

        foreach ($item in $PSBoundParameters['Path']) {

            $checkExists = Resolve-Path $item -ErrorAction SilentlyContinue
            if ($checkExists) {
                
                try {
                    $verifyType = Get-Item -Path $checkExists.Path
                    if ($verifyType.GetType().FullName -eq 'System.IO.DirectoryInfo') {
                        [System.IO.Directory]::EnumerateFiles($verifyType.FullName) | Out-Null
                    }
                    else {
                        $touch = [System.IO.File]::Open($checkExists.Path, [System.IO.FileMode]::Open) # Update the last accessed timestamp akin to BASH
                        $touch.Close()
                    }
                }
                catch [UnauthorizedAccessException] {
                    Write-Host "Access denied." -ForegroundColor Red
                }
                catch {
                    Write-Error -Exception $_.Exception
                }

            }
            else {

                try {
                    New-Item -ItemType File -Path $item
                }
                catch {
                    Write-Error -Exception $_.Exception
                }

            }
        }

    }
    
}

function socks {
	
    [CmdletBinding(DefaultParameterSetName = 'On')]
    param (
        [Parameter(Mandatory = $true, ParameterSetName = 'On')]
        [ValidateNotNullOrEmpty()]
        [String]
        $Username,

        [Parameter(Mandatory = $true, ParameterSetName = 'On')]
        [ValidateNotNullOrEmpty()]	
        [String]
        $ComputerName,

        [Parameter(ParameterSetName = 'On')]
        [ValidateNotNullOrEmpty()]	
        [String]
        $PrivateKeyFile,

        [Parameter(ParameterSetName = 'On')]
        [ValidateRange(1,65535)]
        [Int]
        $SSHPort = 22,

        [Parameter(ParameterSetName = 'On')]
        [ValidateRange(1,65535)]
        [Int]
        $TunnelPort = 1337,

        [Parameter(ParameterSetName = 'Off')]
        [Switch]
        $Off,

        [Parameter(ParameterSetName = 'Status')]
        [Switch]
        $Status
    )
    if ($env:OS -notlike '*Windows*') {
        throw "This function is designed to work only on Windows hosts at the moment."
    }
    elseif ($Off.IsPresent) {
        Set-Itemproperty -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value ''
	    Set-Itemproperty -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
        Get-CimInstance -ClassName Win32_Process | 
            Where-Object {$_.Name -eq 'ssh.exe'} | 
            Where-Object {$_.CommandLine -like '*ssh*-f -C -q -N -D*'} | 
            ForEach-Object {Stop-Process -Id $_.ProcessId -Force}
    }
    elseif ($Status.IsPresent) {
        $checkProxyUp = Get-CimInstance -ClassName Win32_Process | Where-Object {$_.Name -eq 'ssh.exe'} | Where-Object {$_.CommandLine -like '*ssh*-f -C -q -N -D*'}
        if ($checkProxyUp) { return 'Up' }
        else { return 'Down' }
    }
    else {
        $checkProxyUp = Get-CimInstance -ClassName Win32_Process | Where-Object {$_.Name -eq 'ssh.exe'} | Where-Object {$_.CommandLine -like '*ssh*-f -C -q -N -D*'}
        if ($checkProxyUp ) {
            return
        }
        else {
            Set-Itemproperty -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "socks=localhost`:$TunnelPort"
            Set-Itemproperty -Path "HKCU:Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
            if ($PrivateKeyFile) {
                Start-Process ssh -LoadUserProfile -ArgumentList "-i $PrivateKeyFile $Username@$ComputerName -p $SSHPort -f -C -q -N -D $TunnelPort" -NoNewWindow
            }
            else {
                Start-Process ssh -LoadUserProfile -ArgumentList "$Username@$ComputerName -p $SSHPort -f -C -q -N -D $TunnelPort" -NoNewWindow
            }
        }
    }

}

#####################
###### Modules ######
#####################

Write-Host "Importing modules:" -ForegroundColor Green
Write-Host "PSToolbox"
Import-Module PSToolbox

#####################
###### Aliases ######
#####################

Set-Alias clipboard Set-Clipboard
Set-Alias gclip Get-Clipboard
Set-Alias sclip Set-Clipboard
Set-Alias cfjson ConvertFrom-Json
Set-Alias ctjson ConvertTo-Json
Set-Alias iclixml Import-Clixml
Set-Alias eclixml Export-Clixml
Set-Alias cfb64 ConvertFrom-Base64
Set-Alias ctb64 ConvertTo-Base64
Set-Alias ctss ConvertTo-SecureString
Set-Alias cfss ConvertFrom-SecureString
Set-Alias ctcsv ConvertTo-Csv
Set-Alias cfcsv ConvertFrom-Csv
Set-Alias cthtml ConvertTo-Html

#####################
#### Environment ####
#####################

if ($env:OS -like '*Windows*') {
    $apiClientId = "$env:USERPROFILE\Desktop\bitwarden-api-client-id.clixml"
    $apiClientSecret = "$env:USERPROFILE\Desktop\bitwarden-api-client-secret.clixml"
    $encryptedMasterPW = "$env:USERPROFILE\Desktop\bitwarden-master.clixml"
    if (-not (Test-Path $apiClientId)) {
        $clientId = Read-Host -Prompt "Enter BitWarden API client ID"
        $clientId | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml $apiClientId
    }  
    if (-not (Test-Path $apiClientSecret)) {
        $clientId = Read-Host -Prompt "Enter BitWarden API client secret"
        $clientId | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml $apiClientSecret
    }
    if (-not (Test-Path $encryptedMasterPW)) {
        $clientId = Read-Host -Prompt "Enter BitWarden master password"
        $clientId | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml $encryptedMasterPW
    }
    
    $env:BW_CLIENTID = Import-Clixml $apiClientId | ConvertFrom-SecureString
    $env:BW_CLIENTSECRET = Import-Clixml $apiClientSecret | ConvertFrom-SecureString
    $bwStatus = bw status | ConvertFrom-Json
    if ($bwStatus.Status -eq 'unauthenticated') {
        Write-Warning "BitWarden is not authenticated. Attempting to authenticate and unlock."
        $env:BW_PASS = Import-Clixml $encryptedMasterPW | ConvertFrom-SecureString
        bw login --apikey | Out-Null
        $session = bw unlock --passwordenv BW_PASS
        $envString = $session -like '*env:*'
        $bwEnv = $envString.Split('"')[1]
        $env:BW_SESSION = $bwEnv
    }
    else {
        Write-Host "Vault authenticated. Attempting to unlock BitWarden vault." -ForegroundColor Green
        $env:BW_PASS = Import-Clixml $encryptedMasterPW | ConvertFrom-SecureString
        $session = bw unlock --passwordenv BW_PASS
        $envString = $session -like '*env:*'
        $bwEnv = $envString.Split('"')[1]
        $env:BW_SESSION = $bwEnv
        $bwEnv | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml $bwSessionKey -Force
    }

    Remove-Item Env:\BW_CLIENTID -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\BW_CLIENTSECRET -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\BW_PASS -Force -ErrorAction SilentlyContinue
}
if ($PSVersionTable.Platform -eq 'Unix') {
    $apiClientId = "$HOME\bitwarden-api-client-id.clixml"
    $apiClientSecret = "$HOME\bitwarden-api-client-secret.clixml"
    $encryptedMasterPW = "$HOME\bitwarden-master.clixml"
    if (-not (Test-Path $apiClientId)) {
        $clientId = Read-Host -Prompt "Enter BitWarden API client ID"
        $clientId | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml $apiClientId
        chmod 600 $apiClientId
    }  
    if (-not (Test-Path $apiClientSecret)) {
        $clientId = Read-Host -Prompt "Enter BitWarden API client secret"
        $clientId | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml $apiClientSecret
        chmod 600 $apiClientSecret
    }
    if (-not (Test-Path $encryptedMasterPW)) {
        $clientId = Read-Host -Prompt "Enter BitWarden master password"
        $clientId | ConvertTo-SecureString -AsPlainText -Force | Export-Clixml $encryptedMasterPW
        chmod 600 $encryptedMasterPW
    }
    
    $env:BW_CLIENTID = Import-Clixml $apiClientId | ConvertFrom-SecureString
    $env:BW_CLIENTSECRET = Import-Clixml $apiClientSecret | ConvertFrom-SecureString
    $bwStatus = bw status | ConvertFrom-Json
    if ($bwStatus.Status -eq 'unauthenticated') {
        Write-Warning "BitWarden is not authenticated. Attempting to authenticate and unlock."
        $env:BW_PASS = Import-Clixml $encryptedMasterPW | ConvertFrom-SecureString
        bw login --apikey | Out-Null
        $session = bw unlock --passwordenv BW_PASS
        $envString = $session -like '*env:*'
        $bwEnv = $envString.Split('"')[1]
        $env:BW_SESSION = $bwEnv
    }
    else {
        Write-Host "Vault authenticated. Attempting to unlock BitWarden vault." -ForegroundColor Green
        $env:BW_PASS = Import-Clixml $encryptedMasterPW | ConvertFrom-SecureString
        $session = bw unlock --passwordenv BW_PASS
        $envString = $session -like '*env:*'
        $bwEnv = $envString.Split('"')[1]
        $env:BW_SESSION = $bwEnv
    }

    Remove-Item Env:\BW_CLIENTID -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\BW_CLIENTSECRET -Force -ErrorAction SilentlyContinue
    Remove-Item Env:\BW_PASS -Force -ErrorAction SilentlyContinue
}