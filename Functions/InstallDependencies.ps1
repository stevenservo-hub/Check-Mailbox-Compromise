function Install-ModuleDependencies {
    param (
        [string[]]$Modules = @('ConsoleGuiTools')
    )

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
}

Install-ModuleDependencies