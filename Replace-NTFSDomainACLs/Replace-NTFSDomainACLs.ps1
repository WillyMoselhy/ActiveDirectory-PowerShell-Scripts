<#
.SYNOPSIS
This script replaces existing ACLs from a specific domain with entries from a new domain.

.DESCRIPTION
Typical use scenario: You are migrating from an old forest to a new one. Your file shares already have permissions that point
to users and groups in the old domain. Given that you arleady created new users in the new domain with the same SamAccountName,
you can use this script to go through each file and replace existing Access Rules from the old domain with idenitical ones that
point to the new domain.

The script requires cmdlets from the ActiveDirectory module.
For best performance, use local paths instead of network locations. However network URLs are supported.

.EXAMPLE
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare | Out-GridView

This will check the security permissions on each file under the root path, for each file where permissions are not inherited and
the Access Rule belong to objects in OldDomain, the script will try to find a match with the same username in NewDomain. If a 
match is found, the script will add a new rule idenitical to the old one, and remove the OldDomain entry.

The results will be displayed in a Grid View.

.EXAMPLE
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare -CSVLogPath C:\temp\example.csv

Same as the first example, additionally this will save the results in CSV file.
.LINK
https://github.com/WillyMoselhy/ActiveDirectory-PowerShell-Scripts/tree/master/Replace-NTFSDomainACLs

#>

#Requires -Modules ActiveDirectory

Param(
    # Old domain name
    [Parameter(Mandatory = $true)]
    [string] $OldDomainName ,

    # New domain name
    [Parameter(Mandatory = $true)]
    [string] $NewDomainName,

    # Path of folder to replace permissions
    [Parameter(Mandatory = $true)]
    [ValidateScript({Test-Path -Path $_})]
    [string] $RootPath,

    # Path to export results as CSV
    [Parameter(Mandatory = $false)]
    [string] $CSVLogPath
)



$ErrorActionPreference = "Stop"

$RootItem   = [Array] (Get-Item -Path $RootPath)
$ChildItems = [Array] (Get-ChildItem -Path $RootPath -Recurse )
if($ChildItems) {$AllItems = $RootItem + $ChildItems}
else            {$AllItems = $RootItem}

$Count    = 0

$Result = foreach ($Item in $AllItems){
    #Update Progress bar
        $Count++
        $Progress = ($Count/$AllItems.Count)*100
        Write-Progress -Activity "Replacing security permissions of objects from $OldDomainName with $NewDomainName" `
                       -Status   "$Count/$($AllItems.Count) - $($Item.FullName)" `
                       -PercentComplete $Progress

    $ACL = $Item | Get-Acl
    $OldDomainAccessRules = $Acl.Access | Where-Object {$_.IdentityReference.Value -like "$OldDomainName*" -and $_.IsInherited -eq $false}
    if($OldDomainAccessRules){
        $ACLUpdates = 0
        foreach ($OldAccessRule in $OldDomainAccessRules){
            $ObjectName = $OldAccessRule.IdentityReference -replace ".+\\(.+)",'$1'
            $NewDomainADObject = Get-ADObject -Filter {SamAccountName -eq $ObjectName} -Properties CanonicalName
            if ($NewDomainADObject){ #User/group found in new forest
                $ACLUpdates++
                # Add new Acess rule for user in new forest
                $NewAccessRule = New-Object system.security.AccessControl.FileSystemAccessRule("$NewDomainName\$ObjectName",`
                                                                                        $OldAccessRule.FileSystemRights,`
                                                                                        $OldAccessRule.InheritanceFlags,`
                                                                                        $OldAccessRule.PropagationFlags,`
                                                                                        $OldAccessRule.AccessControlType`
                                                                                       )
                $ACL.AddAccessRule($NewAccessRule)
    
                # Remove old access rule for user in old forest
                $ACL.RemoveAccessRule($OldAccessRule) | Out-Null
    

    
                #Return result
                [PSCustomObject]@{
                    Type                = "ACL Entry"
                    Path                = $Item.FullName
                    OldForestObjectName = $ObjectName
                    FoundInNewForest    = $true
                    ObjectType          = $NewDomainADObject.ObjectClass
                    CanonicalName       = $NewDomainADObject.CanonicalName               
                    ACLUpdated          = ""
    
                }
    
            }
            else{ #User / group not found in new forest
                [PSCustomObject]@{
                    Type                = "ACL Entry"
                    Path                = $Item.FullName
                    OldForestObjectName = $ObjectName
                    FoundInNewForest    = $false
                    ObjectType          = ""
                    CanonicalName       = ""
                    ACLUpdated          = ""
                }            
            }

        }

        # Set the ACL
        if($ACLUpdates -gt 0){
            try{
                Set-Acl -Path $Item.FullName -AclObject $ACL -ErrorAction Stop
                $ACLUpdated = $true        
            }
            Catch{
                $ACLUpdated = $Error[0].Exception.Message
            }


            [PSCustomObject]@{
                Type                = "ACL Update"
                Path                = $Item.FullName
                OldForestObjectName = ""
                FoundInNewForest    = ""
                CanonicalName       = ""
                ObjectType          = ""
                ACLUpdated          = $ACLReplaced

            }
        }

    }
}

if ($Result){
    if($CSVLogPath) {$Result | Export-Csv -Path $CSVLogPath -NoTypeInformation -Force -ErrorAction Continue}
    return $Result
}
else {
    Write-Warning "No changes were applied."
}
