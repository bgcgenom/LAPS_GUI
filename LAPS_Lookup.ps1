
#Requires -Version 5.1
<#
.SYNOPSIS
    Legacy LAPS Password Lookup v1.3

.DESCRIPTION
    Read-only Windows PowerShell GUI for retrieving Legacy
    Microsoft LAPS passwords from Active Directory.

    Discovers a domain controller automatically and uses
    credentials supplied by the operator.

.REQUIREMENTS
    Windows PowerShell 5.1
    Active Directory RSAT module
    Network access to Active Directory Web Services
    Permission to read Legacy LAPS password attributes

.NOTES
    No domains, domain controllers, or credentials are stored.
    This tool supports Legacy LAPS (ms-Mcs-AdmPwd) only.
#>

# Prevent unnecessary AD: drive initialization.
$env:ADPS_LoadDefaultDrive = '0'

Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
catch {
    [System.Windows.MessageBox]::Show(
        "The Active Directory PowerShell module is required.",
        "Missing Requirement",
        "OK",
        "Error"
    ) | Out-Null
    return
}

# Session state
$script:Credential = $null
$script:CurrentPassword = $null
$script:CopiedPassword = $null
$script:PasswordVisible = $false
$script:ConnectedDomain = ""
$script:DomainController = ""

# Validate Active Directory DNS domain
function Test-DomainName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    if ($Name.Length -gt 253) {
        return $false
    }

    return $Name -match (
        '^(?=.{1,253}$)' +
        '(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+' +
        '[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
}

# Validate computer name (short name or FQDN)
function Test-ComputerName {
    param([string]$Name)

    if ([string]::IsNullOrWhiteSpace($Name)) {
        return $false
    }

    if ($Name.Length -gt 253) {
        return $false
    }

    return $Name -match '^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$'
}

# Discover a reachable domain controller with ADWS
function Find-LapsDomainController {
    param(
        [Parameter(Mandatory)]
        [string]$Domain
    )

    $Records = @(
        Resolve-DnsName `
            -Name "_ldap._tcp.dc._msdcs.$Domain" `
            -Type SRV `
            -ErrorAction Stop |
        Where-Object { $_.NameTarget } |
        Sort-Object Priority, NameTarget
    )

    foreach ($Record in $Records) {
        $Server = $Record.NameTarget.TrimEnd('.')
        $Client = New-Object System.Net.Sockets.TcpClient
        $AsyncResult = $null

        try {
            $AsyncResult = $Client.BeginConnect(
                $Server, 9389, $null, $null
            )

            if ($AsyncResult.AsyncWaitHandle.WaitOne(1500)) {
                $Client.EndConnect($AsyncResult)
                return $Server
            }
        }
        catch {
            # Try another domain controller.
        }
        finally {
            if ($AsyncResult) {
                $AsyncResult.AsyncWaitHandle.Close()
            }
            $Client.Close()
        }
    }

    throw "No reachable domain controller was found on TCP 9389."
}

# GUI
[xml]$Xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        Title="Legacy LAPS Password Lookup"
        Height="570"
        Width="570"
        MinHeight="570"
        MinWidth="520"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResize"
        Background="#FAFAFA">

    <Grid Margin="18">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
        </Grid.RowDefinitions>

        <TextBlock Grid.Row="0"
                   Text="Legacy LAPS Password Lookup"
                   FontSize="19"
                   FontWeight="Bold"
                   Margin="0,0,0,16"/>

        <!-- Domain -->
        <StackPanel Grid.Row="1" Margin="0,0,0,12">
            <TextBlock Text="Active Directory Domain (FQDN)"
                       Margin="0,0,0,4"/>
            <TextBox Name="DomainName"
                     Height="28"
                     FontSize="14"
                     ToolTip="Enter the full DNS domain name, such as contoso.com"/>
        </StackPanel>

        <!-- Credentials -->
        <StackPanel Grid.Row="2"
                    Orientation="Horizontal"
                    Margin="0,0,0,12">
            <Button Name="CredentialButton"
                    Content="AD Credentials..."
                    Width="145"
                    Height="30"/>
            <TextBlock Name="CredentialStatus"
                       Text="Not connected"
                       VerticalAlignment="Center"
                       Margin="12,0,0,0"/>
        </StackPanel>

        <!-- Computer -->
        <StackPanel Grid.Row="3" Margin="0,0,0,12">
            <TextBlock Text="Computer Name"
                       Margin="0,0,0,4"/>
            <TextBox Name="ComputerName"
                     Height="28"
                     FontSize="14"
                     ToolTip="Enter a computer name and press Enter"/>
        </StackPanel>

        <!-- Lookup -->
        <Button Grid.Row="4"
                Name="LookupButton"
                Content="Look Up Password"
                Height="34"
                Margin="0,0,0,12"/>

        <!-- Password -->
        <StackPanel Grid.Row="5" Margin="0,0,0,14">
            <TextBlock Text="Local Administrator Password"
                       Margin="0,0,0,4"/>

            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="70"/>
                    <ColumnDefinition Width="110"/>
                </Grid.ColumnDefinitions>

                <PasswordBox Name="PasswordDisplay"
                             Grid.Column="0"
                             Height="30"
                             IsEnabled="False"/>

                <TextBox Name="VisiblePassword"
                         Grid.Column="0"
                         Height="30"
                         IsReadOnly="True"
                         Visibility="Collapsed"
                         VerticalContentAlignment="Center"/>

                <Button Name="ShowButton"
                        Grid.Column="1"
                        Content="Show"
                        Height="30"
                        Margin="8,0,0,0"
                        IsEnabled="False"/>

                <Button Name="CopyButton"
                        Grid.Column="2"
                        Content="Copy Password"
                        Height="30"
                        Margin="8,0,0,0"
                        IsEnabled="False"/>
            </Grid>
        </StackPanel>

        <!-- Password Details -->
        <Border Grid.Row="6"
                BorderBrush="#DDDDDD"
                BorderThickness="1"
                CornerRadius="4"
                Background="White"
                Padding="12"
                Margin="0,0,0,12">

            <StackPanel>
                <TextBlock Text="Password Information"
                           FontWeight="Bold"
                           Margin="0,0,0,8"/>

                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="110"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <Grid.RowDefinitions>
                        <RowDefinition Height="Auto"/>
                        <RowDefinition Height="Auto"/>
                    </Grid.RowDefinitions>

                    <TextBlock Grid.Row="0"
                               Grid.Column="0"
                               Text="Last Changed:"
                               Margin="0,0,0,8"/>

                    <TextBlock Name="LastChanged"
                               Grid.Row="0"
                               Grid.Column="1"
                               Text="--"
                               Margin="0,0,0,8"/>

                    <TextBlock Grid.Row="1"
                               Grid.Column="0"
                               Text="Expires:"/>

                    <TextBlock Name="Expiration"
                               Grid.Row="1"
                               Grid.Column="1"
                               Text="--"/>
                </Grid>
            </StackPanel>
        </Border>

        <!-- Status -->
        <StackPanel Grid.Row="7">
            <TextBlock Name="ServerStatus"
                       Text="Domain Controller: Not selected"
                       FontSize="11"
                       Foreground="Gray"
                       Margin="0,0,0,5"/>

            <TextBlock Name="StatusText"
                       Text="Enter domain and AD credentials."
                       TextWrapping="Wrap"
                       Foreground="Gray"/>
        </StackPanel>
    </Grid>
</Window>
'@

try {
    $Reader = New-Object System.Xml.XmlNodeReader $Xaml
    $Window = [Windows.Markup.XamlReader]::Load($Reader)
}
catch {
    Write-Error "Unable to load the GUI: $($_.Exception.Message)"
    return
}

# Controls
$DomainName       = $Window.FindName("DomainName")
$CredentialButton = $Window.FindName("CredentialButton")
$CredentialStatus = $Window.FindName("CredentialStatus")
$ComputerName     = $Window.FindName("ComputerName")
$LookupButton     = $Window.FindName("LookupButton")
$PasswordDisplay  = $Window.FindName("PasswordDisplay")
$VisiblePassword  = $Window.FindName("VisiblePassword")
$ShowButton       = $Window.FindName("ShowButton")
$CopyButton       = $Window.FindName("CopyButton")
$LastChanged      = $Window.FindName("LastChanged")
$Expiration       = $Window.FindName("Expiration")
$ServerStatus     = $Window.FindName("ServerStatus")
$StatusText       = $Window.FindName("StatusText")

# Remove the copied password only when it is still ours.
function Clear-LapsClipboard {
    if ($null -ne $script:CopiedPassword) {
        try {
            if ([System.Windows.Clipboard]::ContainsText()) {
                $ClipboardText = [System.Windows.Clipboard]::GetText()

                if ($ClipboardText -ceq $script:CopiedPassword) {
                    [System.Windows.Clipboard]::Clear()
                }
            }
        }
        catch {
            # Clipboard may be locked by another process.
        }
        finally {
            $script:CopiedPassword = $null
        }
    }
}

# Clear previous results
function Clear-Lookup {
    Clear-LapsClipboard

    $script:CurrentPassword = $null
    $script:PasswordVisible = $false

    $PasswordDisplay.Password = ""
    $VisiblePassword.Text = ""
    $VisiblePassword.Visibility = "Collapsed"
    $PasswordDisplay.Visibility = "Visible"

    $ShowButton.Content = "Show"
    $ShowButton.IsEnabled = $false
    $CopyButton.IsEnabled = $false

    $LastChanged.Text = "--"
    $Expiration.Text = "--"
}

# Request credentials
$CredentialButton.Add_Click({
    try {
        $NewCredential = Get-Credential `
            -Message "Enter your Active Directory credentials"

        if ($NewCredential) {
            Clear-Lookup
            $script:Credential = $NewCredential

            $CredentialStatus.Text = $NewCredential.UserName
            $StatusText.Text = "Credentials provided. Ready for lookup."

            $ComputerName.Focus() | Out-Null
        }
    }
    catch {
        $StatusText.Text = "Credential prompt was not completed."
    }
})

# Domain changed
$DomainName.Add_TextChanged({
    $script:ConnectedDomain = ""
    $script:DomainController = ""

    $ServerStatus.Text = "Domain Controller: Not selected"
    Clear-Lookup
    $StatusText.Text = "Ready for lookup."
})

# Computer changed
$ComputerName.Add_TextChanged({
    Clear-Lookup
    $StatusText.Text = "Ready for lookup."
})

# Press Enter in the computer field to run lookup
$ComputerName.Add_KeyDown({
    if ($_.Key -eq [System.Windows.Input.Key]::Return) {
        if (-not [string]::IsNullOrWhiteSpace($ComputerName.Text)) {
            $_.Handled = $true

            $LookupButton.RaiseEvent(
                [System.Windows.RoutedEventArgs]::new(
                    [System.Windows.Controls.Button]::ClickEvent
                )
            )
        }
    }
})

# Lookup password
$LookupButton.Add_Click({
    Clear-Lookup

    $Domain = $DomainName.Text.Trim()
    $Name = $ComputerName.Text.Trim()

    if (-not (Test-DomainName $Domain)) {
        [System.Windows.MessageBox]::Show(
            "Enter a valid Active Directory DNS domain, such as contoso.com.",
            "Invalid Domain",
            "OK",
            "Warning"
        ) | Out-Null
        return
    }

    if (-not (Test-ComputerName $Name)) {
        $StatusText.Text = "Enter a valid computer name."
        return
    }

    if (-not $script:Credential) {
        $StatusText.Text = "Enter your AD credentials first."
        return
    }

    # Accept short computer names or DNS FQDNs.
    $ShortName = $Name.Split('.')[0]

    try {
        $LookupButton.IsEnabled = $false
        $StatusText.Text = "Discovering domain controller..."

        $Window.Dispatcher.Invoke(
            [Action]{},
            [System.Windows.Threading.DispatcherPriority]::Background
        )

        if ($script:ConnectedDomain -ine $Domain -or
            -not $script:DomainController) {

            $script:DomainController = Find-LapsDomainController `
                -Domain $Domain

            $script:ConnectedDomain = $Domain
        }

        $ServerStatus.Text = "Domain Controller: $script:DomainController"
        $StatusText.Text = "Looking up $ShortName..."

        $Window.Dispatcher.Invoke(
            [Action]{},
            [System.Windows.Threading.DispatcherPriority]::Background
        )

        # Read Legacy LAPS attributes.
        $Computer = Get-ADComputer `
            -Identity $ShortName `
            -Server $script:DomainController `
            -Credential $script:Credential `
            -Properties "ms-Mcs-AdmPwd",
                        "ms-Mcs-AdmPwdExpirationTime" `
            -ErrorAction Stop

        $Password = $Computer.'ms-Mcs-AdmPwd'

        if ([string]::IsNullOrEmpty($Password)) {
            $StatusText.Text = "No Legacy LAPS password returned. Check permissions or LAPS configuration."
            return
        }

        # Password remains masked by default.
        $script:CurrentPassword = $Password
        $PasswordDisplay.Password = $Password

        $ShowButton.IsEnabled = $true
        $CopyButton.IsEnabled = $true

        # Expiration timestamp
        $ExpirationValue = $Computer.'ms-Mcs-AdmPwdExpirationTime'

        if ($ExpirationValue) {
            try {
                $ExpirationDate = [DateTime]::FromFileTimeUtc(
                    [long]$ExpirationValue
                ).ToLocalTime()

                $Expiration.Text = $ExpirationDate.ToString(
                    "MM/dd/yyyy hh:mm:ss tt"
                )

                if ($ExpirationDate -lt (Get-Date)) {
                    $Expiration.Text += " (Past Due)"
                    $Expiration.Foreground = "Red"
                }
                else {
                    $Expiration.Foreground = "Black"
                }
            }
            catch {
                $Expiration.Text = "Unable to convert date"
                $Expiration.Foreground = "Black"
            }
        }
        else {
            $Expiration.Text = "Not available"
            $Expiration.Foreground = "Black"
        }

        # Read password attribute replication metadata.
        # This is not a dedicated password-change audit record.
        try {
            $Metadata = Get-ADReplicationAttributeMetadata `
                -Object $Computer.DistinguishedName `
                -Server $script:DomainController `
                -Credential $script:Credential `
                -ErrorAction Stop |
                Where-Object {
                    $_.AttributeName -eq "ms-Mcs-AdmPwd"
                } |
                Select-Object -First 1

            if ($Metadata -and $Metadata.LastOriginatingChangeTime) {
                $LastChanged.Text = (
                    [DateTime]$Metadata.LastOriginatingChangeTime
                ).ToString("MM/dd/yyyy hh:mm:ss tt")
            }
            else {
                $LastChanged.Text = "Not available"
            }
        }
        catch {
            $LastChanged.Text = "Not available"
        }

        $StatusText.Text = "Password retrieved for $ShortName."
    }
    catch {
        $ErrorMessage = $_.Exception.Message

        # Do not include passwords in error messages.
        if ($script:CurrentPassword) {
            $ErrorMessage = $ErrorMessage.Replace(
                $script:CurrentPassword,
                "[REDACTED]"
            )
        }

        $StatusText.Text = "Lookup failed: $ErrorMessage"

        [System.Windows.MessageBox]::Show(
            $ErrorMessage,
            "LAPS Lookup Error",
            "OK",
            "Error"
        ) | Out-Null
    }
    finally {
        $LookupButton.IsEnabled = $true
    }
})

# Show or hide password
$ShowButton.Add_Click({
    if (-not $script:CurrentPassword) {
        return
    }

    if ($script:PasswordVisible) {
        $VisiblePassword.Text = ""
        $VisiblePassword.Visibility = "Collapsed"
        $PasswordDisplay.Visibility = "Visible"

        $ShowButton.Content = "Show"
        $script:PasswordVisible = $false
    }
    else {
        $VisiblePassword.Text = $script:CurrentPassword
        $PasswordDisplay.Visibility = "Collapsed"
        $VisiblePassword.Visibility = "Visible"

        $ShowButton.Content = "Hide"
        $script:PasswordVisible = $true
    }
})

# Copy password to clipboard
$CopyButton.Add_Click({
    if (-not $script:CurrentPassword) {
        return
    }

    try {
        Clear-LapsClipboard

        [System.Windows.Clipboard]::SetText(
            $script:CurrentPassword
        )

        $script:CopiedPassword = $script:CurrentPassword
        $StatusText.Text = "Password copied. Clear clipboard after use."
    }
    catch {
        $StatusText.Text = "Unable to copy password."
    }
})

# Focus computer name when window opens
$Window.Add_ContentRendered({
    $DomainName.Focus() | Out-Null
})

# Cleanup when window closes
$Window.Add_Closed({
    Clear-Lookup
    $script:Credential = $null
    $script:DomainController = ""
    $script:ConnectedDomain = ""
})

# Show GUI
$null = $Window.ShowDialog()
