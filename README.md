# PowerTrust
Collection of PowerShell cmdlets for use on offensive domain controllers

## Cmdlets

This toolkit contains the following tools to help utilize a domain controller in penetration tests to the fullest:

* `Invoke-ReverseBastion`: By far the most powerful tool of the bunch, this cmdlet automates the process of setting up a bastion forest in the attack domain and adding a target domain to it.
* `Find-InterestingRemoteAcl`: Uses the built-in AD cmdlets together with New-PSDrive and Get-Acl to remotely enumerate ACLs on one domain from another
* `Gen-RDPFile`: Uses a multi-line template to automate the process of establishing one-click access to a remote machine
* `Add-TargetDnsForwarder`: Simplifies the proces of adding a conditional forwarder for resolving a remote domain without needing to manually edit configuration files
* `Add-RemoteDnsWildcardRecord`: Automates the process of adding a `*` record to a remote DC
* `Enter-PlaintextWinRMSession`: Wrapper around `Enter-PSSession` that reduces the number of steps necessary to connect from 3 to 1
* `Invoke-PSADSession`: Reflectively loads the Active Directory PowerShell module assembly into a remote PowerShell session and enters it, bypassing the need to add it as an optional Windows feature on the target system
* More to come