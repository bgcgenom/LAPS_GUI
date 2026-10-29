# Legacy LAPS Password Lookup

A Windows PowerShell 5.1 GUI for retrieving Legacy Microsoft Local Administrator Password Solution (LAPS) passwords from Active Directory.

## Features

- Domain-independent configuration
- Automatic domain controller discovery
- Active Directory credential prompt
- Read-only Legacy LAPS password lookup
- Show/Hide password
- Copy password to clipboard
- Password expiration information
- Last password attribute modification timestamp
- Enter key to start a lookup
- No stored credentials or password log files

## Requirements

- Windows PowerShell 5.1
- Windows Presentation Foundation (WPF)
- Active Directory PowerShell module (RSAT)
- DNS and network connectivity to Active Directory
- Active Directory Web Services on TCP 9389
- Permission to retrieve Legacy LAPS passwords

## Usage

Run:

`powershell.exe -NoProfile -STA -File ".\LAPS_Lookup.ps1"`

Enter the Active Directory DNS domain, provide authorized credentials, and enter a computer name.

## Limitations

This application supports Legacy LAPS attributes (`ms-Mcs-AdmPwd` and `ms-Mcs-AdmPwdExpirationTime`). It does not support Windows LAPS password attributes or Microsoft Entra ID password retrieval.

Last Changed is derived from Active Directory replication metadata. It is not an independent password-change audit record.

Passwords may temporarily exist in application memory and the Windows clipboard. Clipboard clearing is best-effort and does not guarantee removal from clipboard history or synchronized clipboard services.

## Security

The application performs read-only Active Directory operations. It does not change, rotate, or save passwords to disk.

Use only with accounts authorized to retrieve local administrator passwords.

## License

See the repository's LICENSE file.
