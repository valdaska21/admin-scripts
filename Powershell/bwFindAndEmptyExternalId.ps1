# Script: bwFindAndEmptyExternalId.ps1
# Description: Searches for an organization member by their External ID and clears it.
#              Prompts for confirmation before making any changes.
# Requirements: Organization API credentials (client ID and client secret).
# API Reference: https://bitwarden.com/help/public-api/

# Prompt user to select their Bitwarden server region to set the correct API endpoints
Write-Output "Select Server Region:"
Write-Output "  1) US"
Write-Output "  2) EU"
Write-Output "  3) Self-hosted"
$region = Read-Host 'Enter option (1, 2, or 3)'

switch ($region) {
    '1' {
        $api_url      = 'https://api.bitwarden.com'
        $identity_url = 'https://identity.bitwarden.com'
    }
    '2' {
        $api_url      = 'https://api.bitwarden.eu'
        $identity_url = 'https://identity.bitwarden.eu'
    }
    '3' {
        # Strip trailing slash to avoid double slashes when building endpoint URLs
        $vault_uri    = (Read-Host 'Bitwarden Vault URI').TrimEnd('/')
        $api_url      = "$vault_uri/api"
        $identity_url = "$vault_uri/identity"
    }
    default {
        Write-Output "Invalid option. Please enter 1, 2, or 3."
        exit 1
    }
}

# Collect organization API credentials and the external ID to search for
$org_client_id     = Read-Host 'Organization Client ID'
$org_client_secret = Read-Host 'Organization Client Secret (Hidden)' -AsSecureString
# Convert the secure string to plain text for use in the API request body
$org_client_secret = [System.Net.NetworkCredential]::new('', $org_client_secret).Password
$user_external_id  = Read-Host 'External ID to query'

# Authenticate using OAuth2 client credentials flow to obtain a Bearer token
$body = @{
    grant_type    = 'client_credentials'
    scope         = 'api.organization'
    client_id     = $org_client_id
    client_secret = $org_client_secret
}

$response     = Invoke-RestMethod -Uri "$identity_url/connect/token" -Method POST -ContentType 'application/x-www-form-urlencoded' -Body $body
$ACCESS_TOKEN = $response.access_token

# Build headers used for all subsequent API calls
$headers = @{
    'Content-Type' = 'application/json'
    'Accept'       = 'application/json'
    Authorization  = "Bearer $ACCESS_TOKEN"
}

# Fetch all organization members and filter by the provided external ID
$membersData = Invoke-RestMethod -Uri "$api_url/public/members/" -Headers $headers
$matched     = $membersData.data | Where-Object { $_.externalId -eq $user_external_id }

Write-Output ""
Write-Output "Members with that External ID:"

if (-not $matched) {
    Write-Output "No members found with External ID: $user_external_id"
    exit 1
}

foreach ($member in $matched) {
    Write-Output "$($member.id),$($member.email)"
}

Write-Output ""

$member_id = $matched[0].id
$email     = $matched[0].email

$answer = Read-Host "Do you want to empty the external ID of $email? (Y/N)"

if ($answer -eq 'Y' -or $answer -eq 'y') {
    Write-Output "You chose YES. Performing the action..."
    Write-Output "Emptying externalID of $email"

    # Fetch the full member record so all existing fields are preserved in the PUT request
    $member_data = Invoke-RestMethod -Method GET -Uri "$api_url/public/members/$member_id" -Headers $headers

    # Build the update payload, carrying over all fields and setting externalId to null
    $params = @{
        type                  = $member_data.type
        accessAll             = $member_data.accessAll
        externalId            = $null
        resetPasswordEnrolled = $member_data.resetPasswordEnrolled
        collections           = $member_data.collections
    } | ConvertTo-Json

    Invoke-RestMethod -Method PUT -Uri "$api_url/public/members/$member_id" -Headers $headers -Body $params
} elseif ($answer -eq 'N' -or $answer -eq 'n') {
    Write-Output "You chose NO. Exiting..."
    exit 1
} else {
    Write-Output "Invalid response. Please answer with Y or N."
    exit 1
}
