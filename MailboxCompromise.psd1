@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'MailboxCompromise.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = 'd3b3a8b2-5c4b-4e2b-8c3e-2f3b2a8b2d3b'

    # Author of this module
    Author = 'Your Name'

    # Company or vendor of this module
    CompanyName = 'Your Company'

    # Description of the functionality provided by this module
    Description = 'A module to check for mailbox compromise using a GUI interface.'

    # Functions to export from this module
    FunctionsToExport = @('Check-MailboxCompromise', 'Install-ModuleDependencies')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
    }
}