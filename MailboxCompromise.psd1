@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'MailboxCompromise.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = 'bdecf894-f3c9-43ba-88bf-a49908e0445c'

    # Author of this module
    Author = 'Steven SPring'

    # Company or vendor of this module
    CompanyName = ''

    # Copyright statement for this module
    Copyright = '(c) 2024 Steven Spring. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Checks for potential signs of mailbox compromise.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules = @('ExchangeOnlineManagement')

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @()

    # Functions to export from this module
    FunctionsToExport = @('Invoke-mailboxcheck')

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # DSC resources to export from this module
    DscResourcesToExport = @()

    # List of all modules packaged with this module
    NestedModules = @()

    # Prerelease string for this module
    PrivateData = @{}
}
