[CmdletBinding()]
Param ()

if ($PSVersionTable.PSVersion.Major -lt 3)
{
	Throw "PowerShell version 3 or higher is required."
}

$LogName = $PSCommandPath -replace ".ps1", "-"
$TranscriptLogFile = $($LogName + (Get-Date -Format "yyyyMMdd") + ".log")
if (Test-Path -Path $TranscriptLogFile)
{
	Clear-Content -Path $TranscriptLogFile
}
Start-Transcript -Path $TranscriptLogFile

$ServiceName = "WinRM"
$Protocol = "HTTPS"

Write-Verbose -Message "Enabling PSRemoting"
Enable-PSRemoting -SkipNetworkProfileCheck -Force

Write-Verbose -Message "Enabling CredSSP authentication"
Set-Item -Path WSMan:\localhost\Service\Auth\CredSSP -Value $true

Write-Verbose -Message "Enabling Certificate authentication"
Set-Item -Path WSMan:\localhost\Service\Auth\Certificate -Value $true

Write-Verbose -Message "Removing HTTP listener"
Remove-WSManInstance winrm/config/Listener -SelectorSet @{ Address = "*"; Transport = "http" }

Write-Verbose -Message "Request and install a machine certificate from the Enterprise CA for $ServiceName HTTPS listener"
$FQDN = $($Env:COMPUTERNAME + "." + $env:USERDNSDOMAIN).ToLower()
$ShortName = $($env:COMPUTERNAME).ToLower()
$Cert = Get-Certificate -Template VMWareCertificate -DnsName $FQDN,$ShortName -Url "ldap:///CN=DC2" -SubjectName $("CN=" + $FQDN) -CertStoreLocation Cert:\LocalMachine\My

Write-Verbose -Message "Gathering certificate thumbprint"
$Thumbprint = $Cert.Certificate.Thumbprint

Write-Verbose -Message "Enabling HTTPS listener."
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * -CertificateThumbPrint $Thumbprint -Force | Out-Null

Write-Verbose -Message "Verifying $ServiceName service."
if (!(Get-Service -Name $ServiceName))
{
	Throw "Unable to find the $ServiceName service."
}
else
{
	if ((Get-Service -Name $ServiceName).Status -eq "Running")
	{
		Get-Service -Name $ServiceName | Stop-Service | Out-Null
	}
	Write-Verbose "Setting $ServiceName service to start automatically on boot."
	#Set-Service -Name $ServiceName -StartupType Automatic
	Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" | Set-ItemProperty -Name "Start" -Value 2
	Write-Verbose -Message "Configuring $ServiceName service to delayed start"
	Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" | Set-ItemProperty -Name "DelayedAutoStart" -Value 1
	Write-Verbose "Starting $ServiceName service."
	Start-Service -Name $ServiceName -ErrorAction Stop
}


$RuleDisplayName = "Windows Remote Management ($Protocol-In)"
if (-not (Get-NetFirewallRule -DisplayName $ruleDisplayName -ErrorAction Ignore))
{
	$NewRuleParams = @{
		DisplayName   = $RuleDisplayName
		Direction	  = 'Inbound'
		LocalPort	  = 5986
		RemoteAddress = 'Any'
		Protocol	  = 'TCP'
		Action	      = 'Allow'
		Enabled	      = 'True'
		Group		  = 'Windows Remote Management'
	}
	Write-Verbose -Message "Creating windows firewall rule for '$ruleDisplayName'"
	$null = New-NetFirewallRule @NewRuleParams
}

$Protocol = "HTTP"
$RuleDisplayName = "Windows Remote Management ($Protocol-In)"

Write-Verbose -Message "Disabling firewall rules for $RuleDisplayName"
Get-NetFirewallRule -DisplayName "Windows Remote Management (HTTP-In)" | Disable-NetFirewallRule

Write-Verbose -Message "Restarting $ServiceName"
Restart-Service -Name $ServiceName

Write-Verbose -Message "Stopping session transcript."
Stop-Transcript