# Function definitions

function Reset-Password {   
    param (
        [string] $user,
        [string] $Admin,
        [switch] $asciiart
    )
    
    AsciiArt

    try {
                
        Connect-ExchangeOnline -UserPrincipalName $Admin -WarningAction SilentlyContinue
    
        $newPassword = [System.Web.Security.Membership]::GeneratePassword(12, 2)
        
        Set-Mailbox -Identity $user -Password (ConvertTo-SecureString -String $newPassword -AsPlainText -Force)
        
        # Write the password reset. Exchange online is a secure session using HTTPS, so we don't need to worry about plaintext passwords.
        Write-Output "Password for user $user has been reset to $newPassword"
        # Password will not be logged to the log file to ensure security.
        Write-Log "Password for user $user has been reset successfully."
    } catch {
        Write-Log "Failed to reset password for user $user. Error: $_"
        Write-Output "Failed to reset password for user $user. Error: $_"
    }
}

function Revoke-Session {
    param(
        [string]$Admin,
        [string]$user,
        [switch]$AsciiArt
    )

    AsciiArt

    try {
        $AdminCredential = Get-Credential -Message "Enter Exchange Admin credentials"

        Connect-AzureAD -Credential $AdminCredential

        # Revoke the user's refresh tokens
        $getuser = Get-AzureADUser -UserPrincipalName $user
        Revoke-AzureADUserAllRefreshToken -ObjectId $getuser.ObjectId

        Write-Output "Session for user $user has been revoked successfully."
    } catch {
        Write-Log "Failed to revoke session for user $user. Error: $_"
        Write-Output "Failed to revoke session for user $user. Error: $_"
    }
}

function EmailSearch {
    param (
        [string] $UniqUser,
        [string] $EmailSearch,
        [switch] $AsciiArt
    )
    Try {
        Write-Output "Searching for emails received from and responded to $EmailSearch..."

        $receivedEmails = Search-Mailbox -Identity $User -SearchQuery "from:$EmailSearch" -LogOnly -LogLevel Full
        Write-Output "Received emails from $EmailSearch : $($receivedEmails.ResultItems.Count)"

        $respondedEmails = Search-Mailbox -Identity $User -SearchQuery "to:$EmailSearch" -LogOnly -LogLevel Full
        Write-Output "Responded emails to $EmailSearch : $($respondedEmails.ResultItems.Count)"
    } catch {
        Write-Output "An error occurred while searching for emails: $_"
    }
}

function ContentSearch {
    param (
        [string] $UniqUser,
        [string] $ContentSearch,
        [datetime] $StartDate,
        [datetime] $EndDate,
        [switch] $AsciiArt
    )

    AsciiArt

    try {
        Write-Output "Searching for emails containing $ContentSearch..."

        # Build the search query
        $searchQuery = "Content:$ContentSearch"
        if ($StartDate) {
            $searchQuery += " AND Received>=$($StartDate.ToString('yyyy-MM-dd'))"
        }
        if ($EndDate) {
            $searchQuery += " AND Received<=$($EndDate.ToString('yyyy-MM-dd'))"
        }

        $contentSearchResults = Search-Mailbox -Identity $UniqUser -SearchQuery $searchQuery -LogOnly -LogLevel Full
        Write-Output "Emails containing $ContentSearch : $($contentSearchResults.ResultItems.Count)"
        foreach ($result in $contentSearchResults.ResultItems) {
            Write-Output "Subject: $($result.Subject), Received: $($result.ReceivedTime)"
            Write-Log -Message "Subject: $($result.Subject), Received: $($result.ReceivedTime)"
        }
    }
    catch {
        Write-Output "An error occurred while searching for emails: $_"
    }
}

function Write-Log {
    param (
        [string]$Message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $Message"
    Add-Content -Path $global:LogFilePath -Value $logMessage
}