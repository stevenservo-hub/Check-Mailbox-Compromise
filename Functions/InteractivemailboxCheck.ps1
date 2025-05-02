Import-Module ConsoleGuiTools

function Show-MailboxCheckTUI {
    $form = New-ConsoleGuiForm -Title "Mailbox Compromise Checker" -Width 80 -Height 25

    $adminInput = New-ConsoleGuiTextBox -Label "Exchange Admin (UPN):" -Width 40 -X 2 -Y 2
    $userInput = New-ConsoleGuiTextBox -Label "Specific User (optional):" -Width 40 -X 2 -Y 4
    $emailSearchInput = New-ConsoleGuiTextBox -Label "Email Search (optional):" -Width 40 -X 2 -Y 6
    $contentSearchInput = New-ConsoleGuiTextBox -Label "Content Search (optional):" -Width 40 -X 2 -Y 8
    $startDateInput = New-ConsoleGuiTextBox -Label "Start Date (optional, yyyy-MM-dd):" -Width 40 -X 2 -Y 10
    $endDateInput = New-ConsoleGuiTextBox -Label "End Date (optional, yyyy-MM-dd):" -Width 40 -X 2 -Y 12

    $quickRunCheckbox = New-ConsoleGuiCheckBox -Label "Quick Run (Inbox Rules, Logins, Forwarding)" -X 2 -Y 14
    $verboseCheckbox = New-ConsoleGuiCheckBox -Label "Verbose (Detailed Logs)" -X 2 -Y 15
    $passResetCheckbox = New-ConsoleGuiCheckBox -Label "Reset Password" -X 2 -Y 16
    $revokeSessionCheckbox = New-ConsoleGuiCheckBox -Label "Revoke Session" -X 2 -Y 17

    $submitButton = New-ConsoleGuiButton -Label "Run Check" -X 2 -Y 19 -OnClick {
        $admin = $adminInput.Text
        $user = $userInput.Text
        $emailSearch = $emailSearchInput.Text
        $contentSearch = $contentSearchInput.Text
        $startDate = $startDateInput.Text
        $endDate = $endDateInput.Text
        $quickRun = $quickRunCheckbox.Checked
        $verbose = $verboseCheckbox.Checked
        $passReset = $passResetCheckbox.Checked
        $revokeSession = $revokeSessionCheckbox.Checked

        if (-not $admin) {
            Show-ConsoleGuiMessageBox -Title "Error" -Message "Exchange Admin (UPN) is required!" -Width 40 -Height 5
            return
        }

        $command = "Invoke-MailboxCheck -Admin '$admin'"
        if ($user) { $command += " -User '$user'" }
        if ($emailSearch) { $command += " -EmailSearch '$emailSearch'" }
        if ($contentSearch) { $command += " -ContentSearch '$contentSearch'" }
        if ($startDate) { $command += " -StartDate '$startDate'" }
        if ($endDate) { $command += " -EndDate '$endDate'" }
        if ($quickRun) { $command += " -QuickRun" }
        if ($verbose) { $command += " -Verbose" }
        if ($passReset) { $command += " -PassReset" }
        if ($revokeSession) { $command += " -RevokeSession" }

        $output = Invoke-Expression $command
        Show-ConsoleGuiMessageBox -Title "Command Output" -Message ($output -join "`n") -Width 60 -Height 15
    }

    $form.Controls.AddRange(@(
        $adminInput, $userInput, $emailSearchInput, $contentSearchInput,
        $startDateInput, $endDateInput, $quickRunCheckbox, $verboseCheckbox,
        $passResetCheckbox, $revokeSessionCheckbox, $submitButton
    ))

    Show-ConsoleGuiForm -Form $form
}

Show-MailboxCheckTUI