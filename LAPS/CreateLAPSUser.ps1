<#
.SYNOPSIS
Creates a local Windows user with a specified name and a random complex password.

.DESCRIPTION
This script creates a new local Windows user account with a given username. If the user already exists, the script does nothing. Otherwise, it generates a random 24-character complex password and creates the user with these credentials.

.PARAMETER UserName
The username for the new local Windows user account.

.EXAMPLE
.\script.ps1 -UserName "NewUser"
Creates a local user named "NewUser" with a random complex password.

.NOTES
Author: [Your Name]
Date:   [Date of Creation]

#>

# Define parameters for the script
param (
    [Parameter(Mandatory=$true)]
    [string]$UserName
)

# Function to generate a random complex password
function Get-RandomPassword {
    param (
        [int]$length = 24
    )
    $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_-+=<>?'
    $password = -join ((1..$length) | ForEach-Object { Get-Random -Maximum $characters.Length | ForEach-Object { $characters[$_]} })
    return $password
}

# Main script logic
function New-LocalUserWithRandomPassword {
    Param (
        [string]$UserName
    )

    # Check if the user already exists
    $userExists = $false
    try {
        $existingUser = Get-LocalUser -Name $UserName -ErrorAction Stop
        $userExists = $true
    }
    catch [Microsoft.PowerShell.Commands.UserNotFoundException] {
        $userExists = $false
    }
    catch {
        Write-Error "An unexpected error occurred: $_"
        return
    }

    if ($userExists) {
        Write-Host "User '$UserName' already exists. No action taken."
        return
    }

    # Generate a random complex password
    $password = Get-RandomPassword -length 24

    # Convert the password to a SecureString
    $securePassword = ConvertTo-SecureString $password -AsPlainText -Force

    try {
        # Create the new local user
        New-LocalUser -Name $UserName -Password $securePassword -Verbose

    }
    catch {
        # Error handling
        Write-Error "Failed to create user '$UserName'. Error: $_"
    }
}

# Invoke the user creation function
New-LocalUserWithRandomPassword -UserName $UserName
