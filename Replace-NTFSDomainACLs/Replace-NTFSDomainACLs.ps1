<#
.SYNOPSIS
This script replaces existing ACLs from a specific domain with entries from a new domain.

.DESCRIPTION
Typical use scenario: You are migrating from an old forest to a new one. Your file shares already have permissions that point
to users and groups in the old domain. Given that you already created new users in the new domain with the same SamAccountName,
you can use this script to go through each file and replace existing Access Rules from the old domain with identical ones that
point to the new domain.

The script requires cmdlets from the ActiveDirectory module.
For best performance, use local paths instead of network locations. However network URLs are supported.

.EXAMPLE
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare | Out-GridView

This will check the security permissions on each file under the root path, for each file where permissions are not inherited and
the Access Rule belong to objects in OldDomain, the script will try to find a match with the same username in NewDomain. If a
match is found, the script will add a new rule identical to the old one, and remove the OldDomain entry.

The domain names must be the same as the pre Windows 2000 format, DomainName\Username not Username@domain.com

The results will be displayed in a Grid View.

.EXAMPLE
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare -CSVLogPath C:\temp\example.csv

Same as the first example, additionally this will save the results in CSV file.
.LINK
https://github.com/WillyMoselhy/ActiveDirectory-PowerShell-Scripts/tree/master/Replace-NTFSDomainACLs

#>

#Requires -Modules ActiveDirectory
function Replace-NTFSDomainACLs {
    [CmdletBinding(SupportsShouldProcess)]
    Param(
        # Old domain name
        [Parameter(Mandatory = $true)]
        [string] $OldDomainName ,

        # New domain name
        [Parameter(Mandatory = $true)]
        [string] $NewDomainName,

        # Path of folder to replace permissions
        [Parameter(Mandatory = $true)]
        [ValidateScript( { Test-Path -Path $_ })]
        [string] $RootPath,

        # New domain controller FQDN. Specify this if the script is running from old domain.
        [Parameter(Mandatory = $false)]
        [ValidateScript( { Test-NetConnection -ComputerName $_ -InformationLevel Quiet })]
        [string] $NewDCFQDN,

        # List of exception objects in old domain to skip.
        # This will not replace accounts for defined values.
        # specify as pre Windows 2000 format "OldDomain\Name"
        [string[]] $ExceptionList,

        # List of object (users or groups) to replace
        # This will only replace the accounts for defined values
        # specify as per Windows 2000 format "OldDomain\Name"
        [string[]] $IncludeList,

        # Path to export results as CSV
        [Parameter(Mandatory = $false)]
        [string] $CSVLogPath,

        # Do not remove old permissions
        [switch] $KeepOldPermissions

    )



    $ErrorActionPreference = "Stop"
    function Get-AllTargetItems {
        [CmdletBinding()]
        param (
            [string] $RootPath
        )
        $rootItem = [Array] (Get-Item -Path $RootPath -ErrorAction Stop)
        $childItems = [Array] (Get-ChildItem -Path $RootPath -Recurse )
        if ($childItems) { $allItems = $rootItem + $childItems }
        else { $allItems = $rootItem }

        #output
        $allItems
    }

    function Test-LongPath {
        # Handling for long paths
        [CmdletBinding()]
        param (
            $AllItems
        )
        $longPathItems = $AllItems | Where-Object { $_.FullName.Length -ge 255 }
        if ($longPathItems) {
            Write-Warning "The following items have long paths."
            $longPathItems | ForEach-Object { Write-Output $_.FullName }
            Write-Error -Exception @"
The path is too long. Please use \\?\ or \\?\UNC\ prefix (for Windows 1607+) or use Mapped Drives to shorten the path.
For more info check this link: https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#maximum-path-length-limitation
path: $item.FullName
"@
        }
    }

    # Get all target items
    Write-Verbose -Message "Getting all target items under '$RootPath'"
    $allItems = Get-AllTargetItems -RootPath $RootPath
    Write-Verbose -Message "Found $($allItems.Count) items."

    # Check for long paths
    if ($RootPath -notlike "\\?\*") {
        Write-Verbose -Message "Checking for long paths"
        Test-LongPath -AllItems $allItems
        Write-Verbose -Message "Did not find any long path items"
    }

    if ($NewDCFQDN) {
        #If new DC FQDN is specified, use it when getting the AD Object
        $PSDefaultParameterValues = @{
            "Get-ADObject:Server" = $NewDCFQDN
        }
    }

    $count = 0

    $result = foreach ($item in $allItems) {
        #Update Progress bar
        $count++
        $progress = ($count / $allItems.Count) * 100
        if($count%10 -eq 0){ # Show progress every 10 items to improve performance
            Write-Progress -Activity "Replacing security permissions of objects from $OldDomainName with $NewDomainName" `
            -Status "$count/$($allItems.Count)" `
            -PercentComplete $progress
        }

        Write-Verbose -Message "Checking ACL for: $($item.FullName)"

        try {

            $acl = $item | Get-Acl
            $oldDomainAccessRules = $acl.Access | Where-Object { $_.IdentityReference.Value -like "$OldDomainName*" -and $_.IsInherited -eq $false }

            # Remove accounts that are in the exception list
            if ($ExceptionList) {
                $oldDomainAccessRules = $oldDomainAccessRules | Where-Object { $_.IdentityReference.Value -notin $ExceptionList }
            }

            # Filter by accounts that are in the include list
            if ($IncludeList) {
                $oldDomainAccessRules = $oldDomainAccessRules | Where-Object { $_.IdentityReference.Value -in $IncludeList }
            }

            if ($oldDomainAccessRules) {
                $aclUpdates = 0
                foreach ($oldAccessRule in $oldDomainAccessRules) {
                    $objectName = $oldAccessRule.IdentityReference -replace ".+\\(.+)", '$1'
                    $newDomainADObject = Get-ADObject -Filter { SamAccountName -eq $objectName } -Properties CanonicalName
                    if ($newDomainADObject) {
                        #User/group found in new forest
                        $aclUpdates++
                        # Add new Access rule for user in new forest
                        $NewAccessRule = New-Object system.security.AccessControl.FileSystemAccessRule("$NewDomainName\$objectName", `
                                $oldAccessRule.FileSystemRights, `
                                $oldAccessRule.InheritanceFlags, `
                                $oldAccessRule.PropagationFlags, `
                                $oldAccessRule.AccessControlType`
                        )
                        $acl.AddAccessRule($NewAccessRule)

                        if(-not $KeepOldPermissions){
                            # Remove old access rule for user in old forest
                            $acl.RemoveAccessRule($oldAccessRule) | Out-Null
                        }


                        #Return result
                        [PSCustomObject]@{
                            Type                = "ACL Entry"
                            Path                = $item.FullName
                            OldForestObjectName = $objectName
                            FoundInNewForest    = $true
                            ObjectType          = $newDomainADObject.ObjectClass
                            CanonicalName       = $newDomainADObject.CanonicalName
                            KeepOldPermissions  = $KeepOldPermissions
                            ACLUpdated          = ""
                            ErrorMessage        = ""

                        }
                    }
                    else {
                        #User / group not found in new forest
                        [PSCustomObject]@{
                            Type                = "ACL Entry"
                            Path                = $item.FullName
                            OldForestObjectName = $objectName
                            FoundInNewForest    = $false
                            ObjectType          = ""
                            CanonicalName       = ""
                            KeepOldPermissions  = $true #If object is not found in new domain we will keep the old permission anyway.
                            ACLUpdated          = ""
                            ErrorMessage        = ""
                        }
                    }

                }
                # Set the ACL
                if ($aclUpdates -gt 0) {
                    Write-Verbose -Message "Applying $aclUpdates updates to the ACL"
                    try {
                        <#
                        if($PSCmdlet.ShouldProcess()){
                            Set-Acl -Path $item.FullName -AclObject $acl -ErrorAction Stop
                        }
                        else {
                            Set-Acl -Path $item.FullName -AclObject $acl -ErrorAction Stop -WhatIf
                        }
                        #>
                        Set-Acl -Path $item.FullName -AclObject $acl -ErrorAction Stop -WhatIf:$WhatIfPreference

                        $aclUpdated = $true
                        if($WhatIfPreference){
                            $errorMessage = "WhatIf enabled. No changes applied"
                        }
                        else{
                            $errorMessage = ""
                        }

                    }
                    Catch {
                        $aclUpdated = $false
                        $errorMessage = $Error[0].Exception.Message
                    }
                    [PSCustomObject]@{
                        Type                = "ACL Update"
                        Path                = $item.FullName
                        OldForestObjectName = ""
                        FoundInNewForest    = ""
                        CanonicalName       = ""
                        ObjectType          = ""
                        ACLUpdated          = $aclUpdated
                        ErrorMessage        = "$errorMessage"

                    }
                }
            }
        }
        catch {
            $errorMessage = $Error[0].Exception.Message
            [PSCustomObject]@{
                Type                = "Error"
                Path                = $item.FullName
                OldForestObjectName = ""
                FoundInNewForest    = ""
                CanonicalName       = ""
                ObjectType          = ""
                ACLUpdated          = ""
                ErrorMessage        = "$errorMessage"
            }
        }
    }

    if ($result) {
        if ($CSVLogPath) { $result | Export-Csv -Path $CSVLogPath -NoTypeInformation -Force -ErrorAction Continue }

        #output
        $result
    }
    else {
        Write-Warning "No changes were applied."
    }

}
