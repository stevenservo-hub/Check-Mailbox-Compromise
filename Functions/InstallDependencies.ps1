function Install-ModuleDependencies {
    param (
        [string[]]$Modules = @('Microsoft.PowerShell.ConsoleGuiTools')
    )

    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Output "PowerShell 7 or later is required for 'Microsoft.PowerShell.ConsoleGuiTools'. Please update your PowerShell version."
        return
    }

    foreach ($module in $Modules) {
        if (-not (Get-Module -ListAvailable -Name $module)) {
            Write-Output "Module '$module' is not installed. Installing..."
            try {
                Install-Module -Name $module -Force -Scope CurrentUser -ErrorAction Stop
                Write-Output "Module '$module' installed successfully."
            } catch {
                Write-Output "Failed to install module '$module'. Error: $_"
                throw
            }
        } else {
            Write-Output "Module '$module' is already installed."
        }
    }

    # Import the modules
    foreach ($module in $Modules) {
        try {
            Import-Module -Name $module -ErrorAction Stop
            Write-Output "Module '$module' imported successfully."
        } catch {
            Write-Output "Failed to import module '$module'. Error: $_"
            throw
        }
    }
}

Install-ModuleDependencies