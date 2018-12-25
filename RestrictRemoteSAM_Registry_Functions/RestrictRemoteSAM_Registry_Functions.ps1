function Get-DomainRestrictRemoteSAM {
    #Get list of domain controllers in the current domain.
    $DomainControllersList = ((Get-ADDomain).domain |  Get-ADDomainController -filter *).HostName
    
    #Connect to each DC and query the registry property 'RestrictRemoteSAM'
    Invoke-Command -ComputerName $DomainControllersList -ScriptBlock{
        
        #Get the RestrictRemoteSAM property from regstiry, if it does not exist do not show error and put $null in the variable
        $Property = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -ErrorAction SilentlyContinue
        if($Property){ #if property is found
            return [PSCustomObject]@{
                ValueExists      = $true
                Value            = $Property.RestrictRemoteSAM
            }
        }
        else{ #if the property is not set
            return [PSCustomObject]@{
                ValueExists      = $false
                Value            = $null
            }            
        }
    }
}


function Remove-DomainRestrictRemoteSAM {
    #Get list of domain controllers in the current domain.
    $DomainControllersList = ((Get-ADDomain).domain |  Get-ADDomainController -filter *).HostName
    
    #Connect to each DC and delete the registry property 'RestrictRemoteSAM'
    Invoke-Command -ComputerName $DomainControllersList -ScriptBlock{
        
        #Get the RestrictRemoteSAM property from regstiry, if it does not exist do not show error and put $null in the variable
        $Property = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -ErrorAction SilentlyContinue
        
        if($Property){ #Property is set
            $ErrorDeleting = $null #creating empty variable
            
            #Remove the property. If an error occurs put it (the error) in the variable $ErrorDeleting
            Remove-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictRemoteSAM' -ErrorVariable ErrorDeleting -ErrorAction SilentlyContinue
            
            return [PSCustomObject]@{
                ValueExists      = $true
                Value            = $Property.RestrictRemoteSAM #Value before deleting the property
                Deleted          = if(!($ErrorDeleting)) {$true} else {$ErrorDeleting[0].Exception.Message} #If there is an error return its text
            }
        }
        else{
            return [PSCustomObject]@{
                ValueExists      = $false
                Value            = $null
                Deleted          = $null
            }            
        }
    }
}