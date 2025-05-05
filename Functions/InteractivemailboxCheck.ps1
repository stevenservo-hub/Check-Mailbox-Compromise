function Show-MailboxCheckTUI {
    Write-Host "Mailbox Compromise Checker"
    Write-Host "=========================="

    $admin = Read-Host "Enter Exchange Admin (UPN)"
    if (-not $admin) {
        Write-Host "Error: Exchange Admin (UPN) is required!" -ForegroundColor Red
        return
    }

    $user = Read-Host "Enter Specific User (optional)"
    $emailSearch = Read-Host "Enter Email Search (optional)"
    $contentSearch = Read-Host "Enter Content Search (optional)"
    $startDate = Read-Host "Enter Start Date (optional, yyyy-MM-dd)"
    $endDate = Read-Host "Enter End Date (optional, yyyy-MM-dd)"

    $quickRun = Read-Host "Quick Run (Inbox Rules, Logins, Forwarding)? (yes/no)" -eq "yes"
    $verbose = Read-Host "Verbose (Detailed Logs)? (yes/no)" -eq "yes"
    $passReset = Read-Host "Reset Password? (yes/no)" -eq "yes"
    $revokeSession = Read-Host "Revoke Session? (yes/no)" -eq "yes"

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

    Write-Host "Running Command: $command" -ForegroundColor Green
    try {
        $output = Invoke-Expression $command
        Write-Host "Command Output:" -ForegroundColor Cyan
        Write-Host ($output -join "`n")
    } catch {
        Write-Host "Error executing command: $_" -ForegroundColor Red
    }
}

Show-MailboxCheckTUI