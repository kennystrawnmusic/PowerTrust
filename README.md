# PowerTrust
Collection of PowerShell cmdlets for use on offensive domain controllers

## Cmdlets

This toolkit contains the following tools to help utilize an offensively-provisioned domain controller in penetration tests and red team engagements to the fullest:

* `Invoke-ReverseBastion`: By far the most powerful tool of the bunch, this cmdlet automates the process of [setting up a bastion forest in the attack domain and adding a target domain to it](https://www.linkedin.com/pulse/domain-c2er-part-2-attack-mode-kenneth-strawn-aoajc).
* `Find-InterestingRemoteAcl`: Uses the built-in AD cmdlets together with New-PSDrive and Get-Acl to remotely enumerate ACLs on one domain from another, all while using Microsoft-signed tools to avoid detection
* `Gen-RDPFile`: Uses a multi-line template to automate the process of establishing one-click access to a remote machine
* `Add-TargetDnsForwarder`: Simplifies the proces of adding a conditional forwarder for resolving a remote domain without needing to manually edit configuration files
* `Add-RemoteDnsWildcardRecord`: Automates the process of adding a `*` record to a remote DC
* `Enter-PlaintextWinRMSession`: Wrapper around `Enter-PSSession` that reduces the number of steps necessary to connect from 3 to 1
* `Add-RemoteMachineAccount`: Creates a machine account on a target domain from the attack domain, if the MAQ on the target domain is nonzero. Doing it remotely ensures that AV/EDR solutions don't have time to block the tools before the machine account is created.
* `Invoke-PSNetOnly`: Creates a new PowerShell process with logon type 9 (`LOGON_TYPE_NEW_CREDENTIALS`), the same logon type that `runas /netonly` and `Rubeus /createnetonly` use, with a `PSCredential` object instead of a NT hash and/or interactive password prompt. This allows further use of tools like Rubeus and SharpHound remotely from the attack domain with minimal effort.
* More to come
