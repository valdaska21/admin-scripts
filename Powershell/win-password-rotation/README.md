# bitwarden-win-rotation

Based on https://github.com/ab0mbs/bitwarden-ad-rotation

Scripts to rotate passwords of Local Windows Accounts and save them to Bitwarden

These scripts are provided as is and are not guaranteed to work

## Bitwarden_Config.json
- Sets path to log output file
- Sets password length
- Define users and bitwarden items to update

## Bitwarden_Password_Rotation.ps1
- Loops through the users defined
- Gets the items in bitwarden. (They need to be created there first and have unique names)
- Generates a new password
- Saves password to Bitwarden
- Sets local user password
- Logs success and errors to log path
