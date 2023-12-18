<#
    .SYNOPSIS
    Backup all GPO's that have changed since the last time this script was run.
    Cleans up backups older than 30 days.

    .DESCRIPTION
    Script exports and documents the GPO's in Active Directory, writes a CSV file where each GPO has been linked, saves an HTML GPO report, and cleans up old backups.


    .EXAMPLE
    .\GPO-Export-and-Backup.ps1 -BackupFolder -Verbose
#>

param (
    [parameter(ValueFromPipeline)][string]$BackupFolder = $PSScriptRoot
)

# --
# Clean up old backups (older than 30 days)
# --
$cleanupDate = (Get-Date).AddDays(-30)
Get-ChildItem -Path $BackupFolder -Directory | Where-Object { $_.CreationTime -lt $cleanupDate } | ForEach-Object {
    Write-Verbose "Deleting old backup folder: $($_.FullName)"
    Remove-Item $_.FullName -Recurse -Force
}

# --
# Get Date
# --
$FileDate = Get-Date -Format "hh.mm_dd-MM-yyyy"
$GpoFilePath = "$BackupFolder\$FileDate"
If (!(Test-Path -Path $GpoFilePath)) {
    New-Item -Path $GpoFilePath -ItemType Directory | Out-Null
}

# --
# Get latest export date (Only export policy that have changed or added since)
# --
Write-Verbose "Find latest GPO backup in $BackupFolder"
$latestFile = Get-ChildItem -Path $GpoFilePath -File | Sort-Object CreationTime -Descending | Select-Object -First 1

if ($latestFile -ne $null) {
    $LatestExportTime = [DateTime]::ParseExact($latestFile.LastWriteTime.ToShortDateString(), "dd-MM-yyyy", $null)
} else {
    $LatestExportTime = [DateTime]::MinValue
}

# --
# Import modules
# --
Write-Verbose "Import Required modules"
Import-Module ActiveDirectory
Import-Module GroupPolicy

# --
# Get Domain Info
# --
Write-Verbose "Get Domain info and find/makeup SysVol Path"
$Domain = Get-ADDomain
$SysVolFolder = "\\" + $($Domain.DNSRoot) + "\sysvol\" + $($Domain.DNSRoot) + "\Policies\"

# --
# Backup changed Group Policies
# --
Write-Verbose "Get GPO's changed since $LatestExportTime"
$GPOs = Get-GPO -All | Where { $_.ModificationTime -gt $LatestExportTime }



$OutReport = @()
Foreach ($GPO in $GPOs) {
    Write-Verbose "Export $($GPO.DisplayName)"
    $safeDisplayName = $GPO.DisplayName -replace '[<>:"/\|\?\*]+', '_'
    #$safeDisplayName = $GPO.DisplayName -replace '[<>:"/\|\?\*]+', '_' -replace '\s+', '_'
    $gpoExportPath = "$GpoFilePath\$safeDisplayName"

    if (!(Test-Path -Path $gpoExportPath)) {
        New-Item -Path $gpoExportPath -ItemType Directory | Out-Null
    }

    # Proceed with Backup-GPO only if the path is valid
    if (Test-Path -Path $gpoExportPath) {
        Backup-GPO -Guid $GPO.ID -Path $gpoExportPath | Out-Null
    } else {
        Write-Warning "Invalid path for GPO backup: $gpoExportPath"
        continue
    }

    # Copy User and Computer Scripts with -Force to overwrite existing files
    # Replace your existing logic for copying scripts here with -Force parameter

    # Create GPO HTML report
    $reportPath = "$gpoExportPath\$safeDisplayName.html"
    if (!(Test-Path -Path $reportPath)) {
        if ($reportPath.Length -lt 260) {
            Get-GPOReport -ReportType Html -Guid $GPO.ID -Path $reportPath
        } else {
            Write-Warning "Path too long for report: $reportPath"
        }
    } else {
        Write-Verbose "Report already exists, skipping: $reportPath"
    }

    Write-Verbose "Document the OU's where the Policy is linked"
    if (($GPReport.GPO.LinksTo).Count -eq 0) {
        $OutReport += [PSCustomObject]@{
        "Name" = $GPReport.GPO.Name
        "Link" = ""
        "Link Enabled" = ""
        "ComputerEnabled" = $GPReport.GPO.Computer.Enabled
        "UserEnabled" = $GPReport.GPO.User.Enabled
        "WmiFilter" = $GPO.WmiFilter
        "GpoApply" = (Get-GPPermissions -Guid $GPO.ID -All | Where {$_.Permission -eq "GpoApply"}).Trustee.Name
        "SDDL" = $($GPReport.GPO.SecurityDescriptor.SDDL.'#text')
        }
    } else {

        foreach ($i in $GPReport.GPO.LinksTo) {
            $OutReport += [PSCustomObject]@{
            "Name" = $GPReport.GPO.Name
            "Link" = $i.SOMPath
            "Link Enabled" = $i.Enabled
            "ComputerEnabled" = $GPReport.GPO.Computer.Enabled
            "UserEnabled" = $GPReport.GPO.User.Enabled
            "WmiFilter" = $GPO.WmiFilter
            "GpoApply" = (Get-GPPermissions -Guid $GPO.ID -All | Where {$_.Permission -eq "GpoApply"}).Trustee.Name
            "SDDL" = $($GPReport.GPO.SecurityDescriptor.SDDL.'#text')
            }
        }

    }

}
$OutReport | Export-Csv -Path "$BackupFolder\$FileDate-GPO-Link-Report.csv" -NoTypeInformation -Delimiter ";" -Encoding UTF8 
