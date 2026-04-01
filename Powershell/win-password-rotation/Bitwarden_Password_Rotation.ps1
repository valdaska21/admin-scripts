# Depends on file "secureString.txt" which can be created by first running:
# Read-Host "Enter Master Password" -AsSecureString | ConvertFrom-SecureString | Out-File "secureString.txt"
# bw is required in $PATH and logged in but you do not have to unlock it https://bitwarden.com/help/cli/

# Read in config
$config = Get-Content -Path ".\Bitwarden_Config.json" | ConvertFrom-Json

$masterpassword = Get-Content "secureString.txt" | ConvertTo-SecureString
$cred = New-Object System.Management.Automation.PSCredential "null", $masterpassword
$session_key = , $cred.GetNetworkCredential().password | powershell -c 'bw unlock --raw'

bw sync --session $session_key

# Loop through each account to be configured
foreach ($account in $config.accounts) {
    # Initialize variables
    $item = $null
    $generatedPassword = $null
    $encoded = $null
    $updated = $null

    # Check and see if an item already exists in Bitwarden
    $item = & bw get item $account.bitwarden_item --session $session_key

    # Check if we found the item
    if ($null -ne $item) {
        # Convert item from json
        $item = $item | ConvertFrom-Json

        # Generate password for account
        $generatedPassword = & bw generate -ulns --length $config.password_length --raw

        # Set new password on the item
        $item.login.password = $generatedPassword

        # Encode the temp data
        $encoded = $item | ConvertTo-Json -Compress | & bw encode

        # Save to Bitwarden
        $updated = & bw edit item $item.id $encoded --session $session_key

        # Check that the update was successful
        if ($null -ne $updated) {
            $dt = Get-Date -Format s
            Write-Output "$dt - SUCCESS: Updated password in Bitwarden - $($account.bitwarden_item)" | Add-Content -Path $config.log_path

            # Set local user password
            Try {
                
                Set-LocalUser -Name $account.username -Password (ConvertTo-SecureString -AsPlainText $generatedPassword -Force) -ErrorAction Stop
                $dt = Get-Date -Format s
                Write-Output "$dt - SUCCESS: Updated local user password - $($account.username)" | Add-Content -Path $config.log_path
            } Catch {
                $dt = Get-Date -Format s
                Write-Output "$dt - ERROR: Cannot update local user password - $($account.username)" | Add-Content -Path $config.log_path
            }
        } else {
            $dt = Get-Date -Format s
            Write-Output "$dt - ERROR: Cannot update password in Bitwarden - $($account.bitwarden_item)" | Add-Content -Path $config.log_path
        }
    } else {
        $dt = Get-Date -Format s
        Write-Output "$dt - ERROR: Cannot get Bitwarden item - $($account.bitwarden_item)" | Add-Content -Path $config.log_path
    }
}
