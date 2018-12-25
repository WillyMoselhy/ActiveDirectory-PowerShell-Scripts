# Restrict Remote SAM Registry Functions
A new feature in Windows Server 2016 (and available in earlier version by installing an update) adds the policy: 
```
Network access: Restrict clients allowed to make remote calls to SAM
```
These functions check all DCs for the current state of this policy and allows deleting the key from the registry of all DCs in the domain if needed.

You may read about this feature on MS Docs [here](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-clients-allowed-to-make-remote-sam-calls).

The function is desinged to run from any computer in the domain given that the AD PowerShell module is available and the account has sufficient privilages on the DCs

To use it just copy the function into a PowerShell session then use any of the example below.

## Get-DomainRestrictRemoteSAM
Lists the registry value for the property on all DCs in the domain.

**Example**
```PowerShell
Get-DomainRestrictRemoteSAM | Format-Table
```

## Remove-DomainRestrictRemoteSAM
Deletes the property on all DCs in the domain.

**Example**
```PowerShell
Remove-DomainRestrictRemoteSAM | Format-Table
```