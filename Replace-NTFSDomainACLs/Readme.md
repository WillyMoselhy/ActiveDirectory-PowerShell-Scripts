# Replace-NTFSDomainACLs.ps1
## Typical use scenario
You are migrating from an old forest to a new one. Your file shares already have permissions that point
to users and groups in the old domain. Given that you arleady created new users in the new domain with the same SamAccountName,
you can use this script to go through each file and replace existing Access Rules from the old domain with idenitical ones that
point to the new domain.

>The script requires cmdlets from the **ActiveDirectory** module.

>For best performance, use local paths instead of network locations. However network file shares are supported.

**Example 1** Display results in GridView (Does not work on Windows Core)
```PowerShell
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare | Out-GridView
```

This will check the security permissions on each file under the root path, for each file where permissions are not inherited and
the Access Rule belong to objects in OldDomain, the script will try to find a match with the same username in NewDomain. If a
match is found, the script will add a new rule idenitical to the old one, and remove the OldDomain entry.

The results will be displayed in a Grid View.

![Results in GridView](_SupportFiles/Out-GridViewResults.png)

**Example 2** Save results as a CSV
```PowerShell
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare -CSVLogPath C:\temp\example.csv
```

Same as the first example, additionally this will save the results in CSV file.

**Example 3** Run from a server in the old domain
```PowerShell
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare -NewDCFQDN "NewDC.NewDomain.com" | Out-GridView
```

By default the script queries the current domain, so if you running it from a server joined to the old domain you must specify the FQDN of a domain controller in the new domain.

**Example 4** Skip specific users or groups from replacement
```PowerShell
$Exceptions = "OldDomain\Username","OldDomain\Group Name"
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare -ExceptionList $Exceptions | Out-GridView
```

The script will not replace the permissions for any of the accounts in the $Exceptions variable. use comma separated strings.

**Example 5** Include only specific accounts
```PowerShell
$IncludeList = "OldDomain\Username","OldDomain\Group Name"
.\Replace-NTFSDomainACLs.ps1 -OldDomainName "OldDomain" -NewDomainName "NewDomain" -RootPath D:\FileShares\ExampleShare -IncludeList $Exceptions | Out-GridView
```

The script will only replace the accounts in the $IncludeList variable.

**Example 6** Use splatting and `Export-CSV` for timestamped logs
```PowerShell
$RootPath = 'F:\Share'
$LogFolderPath = 'C:\PermissionReplaceLogs'

$params = @{
    OldDomainName      = 'OldContoso'
    NewDomainName      = 'NewContoso'
    RootPath           = $RootPath
    NewDCFQDN          = 'DC1.NewContoso.com'
    KeepOldPermissions = $true #This only duplicates the permissions
    WhatIf             = $false

}
$result = Replace-NTFSDomainACLs @params

$timeStamp = Get-Date -Format "yyyyMMdd-HHmm"
$csvPath = Join-Path -Path $LogFolderPath -ChildPath "$($RootPath -replace "\\","-" -replace ":","-") - $timeStamp.csv"

$result | Export-Csv -Path $csvPath -Encoding Unicode -NoTypeInformation
```
## Handling long file names

The Get-ACL and Set-ACL commands do not function if the file name is longer than 255 characters.

The script will show an error for paths longer than 255 characters. You can review the list by filtering the output and run the script again using one of the below workarounds,
### Script is running on Windows 10 or Windows Server 2016
Beginnig with Windows version 1607 it is possible to use the ```\\?\``` prefix to handle file names longer than 255 characters.
* If you are targetting a local file use this format: ``` \\\\?\C:\Temp\Folder ```
* If you are targetting a file share, use this format: ``` \\\\?\UNC\FileServer\FileShare\Folder ```

More info on this can be found here: [Maximum Path Length Limitation](https://docs.microsoft.com/en-us/windows/desktop/FileIO/naming-a-file#maximum-path-length-limitation)

### Script is running on older versions of Windows

Use mapped drives to shorten the path.