<#
    .DESCRIPTION
    Install required features for DHCP services and Restore scopes and leases, to latest backup file found on the supplied Path

    .PARAMETER Path 
    Specifies where the backup file will be retrived.
    This can be local path or a UNC path.
    
    .EXAMPLE
    .\Setup-Dhcp-Server.ps1 -Path "\\FILE01\Backup\DHCP"
#>


#
# Install Required Features
#
Install-WindowsFeature -name DHCP -IncludeManagementTools

#
# Restore DHCP server
#
$LatestBackup = Get-ChildItem -Path $Path | Sort-Object CreationTime -Descending | Select-Object -First 1
Try {
    Import-DhcpServer -Leases -File "$($LatestBackup.fullname)" -BackupPath "C:\Windows\Temp" -force
} catch {
    Write-Output "Unable to Restore the DHCP server"
    Write-Output $_
}

#
# Authorize new DHCP server
# - Please make sure your account have the correct permissions to do this.
#
Try {
    Add-DHCPServerInDC
} catch {
    Write-Output $_
}

#
# Restart
#
Shutdown -t -t 0
