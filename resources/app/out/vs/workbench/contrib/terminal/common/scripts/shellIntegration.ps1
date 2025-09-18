# ---------------------------------------------------------------------------------------------
#   Copyright (c) Microsoft Corporation. All rights reserved.
#   Licensed under the MIT License. See License.txt in the project root for license information.
# ---------------------------------------------------------------------------------------------

# Prevent installing more than once per session
if ($Global:__VSCodeState.OriginalPrompt -ne $null) {
	return;
}

# Disable shell integration when the language mode is restricted
if ($ExecutionContext.SessionState.LanguageMode -ne "FullLanguage") {
	return;
}

$Global:__VSCodeState = @{
	OriginalPrompt = $function:Prompt
	LastHistoryId = -1
	IsInExecution = $false
	EnvVarsToReport = @()
	Nonce = $null
	IsStable = $null
	IsWindows10 = $false
}

# Store the nonce in a regular variable and unset the environment variable. It's by design that
# anything that can execute PowerShell code can read the nonce, as it's basically impossible to hide
# in PowerShell. The most important thing is getting it out of the environment.
$Global:__VSCodeState.Nonce = $env:VSCODE_NONCE
$env:VSCODE_NONCE = $null

$Global:__VSCodeState.IsStable = $env:VSCODE_STABLE
$env:VSCODE_STABLE = $null

$__vscode_shell_env_reporting = $env:VSCODE_SHELL_ENV_REPORTING
$env:VSCODE_SHELL_ENV_REPORTING = $null
if ($__vscode_shell_env_reporting) {
	$Global:__VSCodeState.EnvVarsToReport = $__vscode_shell_env_reporting.Split(',')
}
Remove-Variable -Name __vscode_shell_env_reporting -ErrorAction SilentlyContinue

$osVersion = [System.Environment]::OSVersion.Version
$Global:__VSCodeState.IsWindows10 = $IsWindows -and $osVersion.Major -eq 10 -and $osVersion.Minor -eq 0 -and $osVersion.Build -lt 22000
Remove-Variable -Name osVersion -ErrorAction SilentlyContinue

if ($env:VSCODE_ENV_REPLACE) {
	$Split = $env:VSCODE_ENV_REPLACE.Split(":")
	foreach ($Item in $Split) {
		$Inner = $Item.Split('=', 2)
		[Environment]::SetEnvironmentVariable($Inner[0], $Inner[1].Replace('\x3a', ':'))
	}
	$env:VSCODE_ENV_REPLACE = $null
}
if ($env:VSCODE_ENV_PREPEND) {
	$Split = $env:VSCODE_ENV_PREPEND.Split(":")
	foreach ($Item in $Split) {
		$Inner = $Item.Split('=', 2)
		[Environment]::SetEnvironmentVariable($Inner[0], $Inner[1].Replace('\x3a', ':') + [Environment]::GetEnvironmentVariable($Inner[0]))
	}
	$env:VSCODE_ENV_PREPEND = $null
}
if ($env:VSCODE_ENV_APPEND) {
	$Split = $env:VSCODE_ENV_APPEND.Split(":")
	foreach ($Item in $Split) {
		$Inner = $Item.Split('=', 2)
		[Environment]::SetEnvironmentVariable($Inner[0], [Environment]::GetEnvironmentVariable($Inner[0]) + $Inner[1].Replace('\x3a', ':'))
	}
	$env:VSCODE_ENV_APPEND = $null
}

# Register Python shell activate hooks
# Prevent multiple activation with guard
if (-not $env:VSCODE_PYTHON_AUTOACTIVATE_GUARD) {
	$env:VSCODE_PYTHON_AUTOACTIVATE_GUARD = '1'
	if ($env:VSCODE_PYTHON_PWSH_ACTIVATE -and $env:TERM_PROGRAM -eq 'vscode') {
		$activateScript = $env:VSCODE_PYTHON_PWSH_ACTIVATE
		Remove-Item Env:VSCODE_PYTHON_PWSH_ACTIVATE

		try {
			Invoke-Expression $activateScript
		}
		catch {
			$activationError = $_
			Write-Host "`e[0m`e[7m * `e[0;103m VS Code Python powershell activation failed with exit code $($activationError.Exception.Message) `e[0m"
		}
	}
}

function Global:__VSCode-Escape-Value([string]$value) {
	# NOTE: In PowerShell v6.1+, this can be written `$value -replace '…', { … }` instead of `[regex]::Replace`.
	# Replace any non-alphanumeric characters.
	[regex]::Replace($value, "[$([char]0x00)-$([char]0x1f)\\\n;]", { param($match)
			# Encode the (ascii) matches as `\x<hex>`
			-Join (
				[System.Text.Encoding]::UTF8.GetBytes($match.Value) | ForEach-Object { '\x{0:x2}' -f $_ }
			)
		})
}

function Global:Prompt() {
	$FakeCode = [int]!$global:?
	# NOTE: We disable strict mode for the scope of this function because it unhelpfully throws an
	# error when $LastHistoryEntry is null, and is not otherwise useful.
	Set-StrictMode -Off
	$LastHistoryEntry = Get-History -Count 1
	$Result = ""
	# Skip finishing the command if the first command has not yet started or an execution has not
	# yet begun
	if ($Global:__VSCodeState.LastHistoryId -ne -1 -and ($Global:__VSCodeState.HasPSReadLine -eq $false -or $Global:__VSCodeState.IsInExecution -eq $true)) {
		$Global:__VSCodeState.IsInExecution = $false
		if ($LastHistoryEntry.Id -eq $Global:__VSCodeState.LastHistoryId) {
			# Don't provide a command line or exit code if there was no history entry (eg. ctrl+c, enter on no command)
			$Result += "$([char]0x1b)]633;D`a"
		}
		else {
			# Command finished exit code
			# OSC 633 ; D [; <ExitCode>] ST
			$Result += "$([char]0x1b)]633;D;$FakeCode`a"
		}
	}
	# Prompt started
	# OSC 633 ; A ST
	$Result += "$([char]0x1b)]633;A`a"
	# Current working directory
	# OSC 633 ; <Property>=<Value> ST
	$Result += if ($pwd.Provider.Name -eq 'FileSystem') { "$([char]0x1b)]633;P;Cwd=$(__VSCode-Escape-Value $pwd.ProviderPath)`a" }

	# Send current environment variables as JSON
	# OSC 633 ; EnvJson ; <Environment> ; <Nonce>
	if ($Global:__VSCodeState.EnvVarsToReport.Count -gt 0) {
		$envMap = @{}
        foreach ($varName in $Global:__VSCodeState.EnvVarsToReport) {
            if (Test-Path "env:$varName") {
                $envMap[$varName] = (Get-Item "env:$varName").Value
            }
        }
        $envJson = $envMap | ConvertTo-Json -Compress
        $Result += "$([char]0x1b)]633;EnvJson;$(__VSCode-Escape-Value $envJson);$($Global:__VSCodeState.Nonce)`a"
	}

	# Before running the original prompt, put $? back to what it was:
	if ($FakeCode -ne 0) {
		Write-Error "failure" -ea ignore
	}
	# Run the original prompt
	$OriginalPrompt += $Global:__VSCodeState.OriginalPrompt.Invoke()
	$Result += $OriginalPrompt

	# Prompt
	# OSC 633 ; <Property>=<Value> ST
	if ($Global:__VSCodeState.IsStable -eq "0") {
		$Result += "$([char]0x1b)]633;P;Prompt=$(__VSCode-Escape-Value $OriginalPrompt)`a"
	}

	# Write command started
	$Result += "$([char]0x1b)]633;B`a"
	$Global:__VSCodeState.LastHistoryId = $LastHistoryEntry.Id
	return $Result
}

# Report prompt type
if ($env:STARSHIP_SESSION_KEY) {
	[Console]::Write("$([char]0x1b)]633;P;PromptType=starship`a")
}
elseif ($env:POSH_SESSION_ID) {
	[Console]::Write("$([char]0x1b)]633;P;PromptType=oh-my-posh`a")
}
elseif ((Test-Path variable:global:GitPromptSettings) -and $Global:GitPromptSettings) {
	[Console]::Write("$([char]0x1b)]633;P;PromptType=posh-git`a")
}

# Only send the command executed sequence when PSReadLine is loaded, if not shell integration should
# still work thanks to the command line sequence
$Global:__VSCodeState.HasPSReadLine = $false
if (Get-Module -Name PSReadLine) {
	$Global:__VSCodeState.HasPSReadLine = $true
	[Console]::Write("$([char]0x1b)]633;P;HasRichCommandDetection=True`a")

	$Global:__VSCodeState.OriginalPSConsoleHostReadLine = $function:PSConsoleHostReadLine
	function Global:PSConsoleHostReadLine {
		$CommandLine = $Global:__VSCodeState.OriginalPSConsoleHostReadLine.Invoke()
		$Global:__VSCodeState.IsInExecution = $true

		# Command line
		# OSC 633 ; E [; <CommandLine> [; <Nonce>]] ST
		$Result = "$([char]0x1b)]633;E;"
		$Result += $(__VSCode-Escape-Value $CommandLine)
		# Only send the nonce if the OS is not Windows 10 as it seems to echo to the terminal
		# sometimes
		if ($Global:__VSCodeState.IsWindows10 -eq $false) {
			$Result += ";$($Global:__VSCodeState.Nonce)"
		}
		$Result += "`a"

		# Command executed
		# OSC 633 ; C ST
		$Result += "$([char]0x1b)]633;C`a"

		# Write command executed sequence directly to Console to avoid the new line from Write-Host
		[Console]::Write($Result)

		$CommandLine
	}

	# Set ContinuationPrompt property
	$Global:__VSCodeState.ContinuationPrompt = (Get-PSReadLineOption).ContinuationPrompt
	if ($Global:__VSCodeState.ContinuationPrompt) {
		[Console]::Write("$([char]0x1b)]633;P;ContinuationPrompt=$(__VSCode-Escape-Value $Global:__VSCodeState.ContinuationPrompt)`a")
	}
}

# Set IsWindows property
if ($PSVersionTable.PSVersion -lt "6.0") {
	# Windows PowerShell is only available on Windows
	[Console]::Write("$([char]0x1b)]633;P;IsWindows=$true`a")
}
else {
	[Console]::Write("$([char]0x1b)]633;P;IsWindows=$IsWindows`a")
}

# Set always on key handlers which map to default VS Code keybindings
function Set-MappedKeyHandler {
	param ([string[]] $Chord, [string[]]$Sequence)
	try {
		$Handler = Get-PSReadLineKeyHandler -Chord $Chord | Select-Object -First 1
	}
 catch [System.Management.Automation.ParameterBindingException] {
		# PowerShell 5.1 ships with PSReadLine 2.0.0 which does not have -Chord,
		# so we check what's bound and filter it.
		$Handler = Get-PSReadLineKeyHandler -Bound | Where-Object -FilterScript { $_.Key -eq $Chord } | Select-Object -First 1
	}
	if ($Handler) {
		Set-PSReadLineKeyHandler -Chord $Sequence -Function $Handler.Function
	}
}

function Set-MappedKeyHandlers {
	Set-MappedKeyHandler -Chord Ctrl+Spacebar -Sequence 'F12,a'
	Set-MappedKeyHandler -Chord Alt+Spacebar -Sequence 'F12,b'
	Set-MappedKeyHandler -Chord Shift+Enter -Sequence 'F12,c'
	Set-MappedKeyHandler -Chord Shift+End -Sequence 'F12,d'
}

# SIG # Begin signature block
# MIIu4QYJKoZIhvcNAQcCoIIu0jCCLs4CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDBVtHBLPwuSgtl
# exw2wvq/u7DblOcuiYM0SuTsPivdDaCCFAgwggYiMIIECqADAgECAhMzAAAAOqVM
# eg/pLY5WAAEAAAA6MA0GCSqGSIb3DQEBCwUAMIGHMQswCQYDVQQGEwJVUzETMBEG
# A1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWlj
# cm9zb2Z0IENvcnBvcmF0aW9uMTEwLwYDVQQDEyhNaWNyb3NvZnQgTWFya2V0cGxh
# Y2UgUHJvZHVjdGlvbiBDQSAyMDExMB4XDTI1MDYxOTE4NTQxNVoXDTI2MDYxNzE4
# NTQxNVowdDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNV
# BAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEeMBwG
# A1UEAxMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEAt+78Zgve1ubGrUDoN6b38AwwRTsG3Se8MLvV19OCgewrUcuR
# EcXHc5cdJM/anZ826GOGXAjdDRwOZVDMHROsFKj2PICU012e5Hjs+p6vwaBPnnnB
# uUuydZaIp2WNSmN/asrooD6J8uQRHGsPbHXCJ6YpJVQoYSWRRVM84NQGv4eSHs0d
# 5oV3V4YTHoZ8Fd3pCARGU+y26WKuqJZKw1QIJQ8cbeQYG3YYLDGAg7FHme8QdOU6
# lB9j8dyYQ5QKsBTcLaHipJjTOs8Xk97Vlp/UdY5AwzynG9BoPiQhpiyuL+txj+tV
# de6H/sixUoHpHkR4bwbtZ2SEmwVnQ8+RdYhWnQIDAQABo4IBlzCCAZMwEwYDVR0l
# BAwwCgYIKwYBBQUHAwMwHQYDVR0OBBYEFLGyVe1sw+70Uzk4ufV2dFPjDoVJMEUG
# A1UdEQQ+MDykOjA4MR4wHAYDVQQLExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFjAU
# BgNVBAUTDTIyOTk3OSs1MDUyOTYwHwYDVR0jBBgwFoAUnqf5oCNwnxHFaeOhjQr6
# 8bD01YAwbAYDVR0fBGUwYzBhoF+gXYZbaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraW9wcy9jcmwvTWljcm9zb2Z0JTIwTWFya2V0cGxhY2UlMjBQcm9kdWN0aW9u
# JTIwQ0ElMjAyMDExKDEpLmNybDB5BggrBgEFBQcBAQRtMGswaQYIKwYBBQUHMAKG
# XWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0
# JTIwTWFya2V0cGxhY2UlMjBQcm9kdWN0aW9uJTIwQ0ElMjAyMDExKDEpLmNydDAM
# BgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4ICAQBBpSDW5NL6rmKT8ftzHOR+
# JbUg6yHKn19WmtZ6eowhPYG8m9cMpGM2+/6eXjX87Pf3UHC0Gqdg/DXnjavS3QAX
# qCLktsYiPdG877xNK3pWA25ZoP6hyIjeh/iFhqCgLDAHERBEb3hghPGep9jTQDxz
# S550721TvdZzLdYuaDKa11J1jxSgX5hKAkWrjHo/rfqSROLcP58zAXeOHPzUKrXW
# mVskEMnczZRTkFBQunCnikWTV8KKap5mNh59Go/Q8TSHvvRudMljYgOQrQZnFQAK
# /v0NOGv81z0jb5yRnK2A+T9SUviNiKtjo7zzproy3vBYdeWWontlFQqhIcSnd1Np
# MjYJEC0PHDS2JdvaJtjyYlPH5+xjAKDQztSazXte0IRyhCnz8dnmJMXzh+zd0hTk
# EuZ8l+3dphYb5CXBVvw7PhkOlAP5zOqPHi9nzuwK/iS4E4iZM5IdI+WY5H6jtzfk
# VxkoaEL6LTMs2bRBgj1eFsi2W/Eiqx0WBjoEFFPRiXTHb0rVLZOM1nbQ4lREsl8d
# pCJhQEBUYt5s6CsPRucMGHP+o4Uy/X2+IWaxxjWNXsc3PEYJGcOgQkp4gbPTQ29h
# YszDwvw9rDlA1X32AENHkJNh7V1EahIdciW/tzKQCf5BIKaYrWAY5Gefp+4iGmcN
# sIiGN7Lh/3VlyxF6dkMPFTCCBtcwggS/oAMCAQICCmESRKIAAAAAAAIwDQYJKoZI
# hvcNAQELBQAwgYgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# MjAwBgNVBAMTKU1pY3Jvc29mdCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAy
# MDExMB4XDTExMDMyODIxMDkzOVoXDTMxMDMyODIxMTkzOVowfTELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNV
# BAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEnMCUGA1UEAxMeTWljcm9zb2Z0IE1h
# cmtldFBsYWNlIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKC
# AgEAubUaSwGYVsE3MAnPfvmozUhAB3qxBABgJRW1vDp4+tVinXxD32f7k1K89JQ6
# zDOgS/iDgULC+yFK1K/1Qjac/0M7P6c8v5LSjnWGlERLa/qY32j46S7SLQcit3g2
# jgoTTO03eUG+9yHZUTGV/FJdRYB8uXhrznJBa+Y+yGwiQKF+m6XFeBH/KORoKFx+
# dmMoy9EWJ/m/o9IiUj2kzm9C691+vZ/I2w0Bj93W9SPPkV2PCNHlzgfIAoeajWpH
# mi38Wi3xZHonkzAVBHxPsCBppOoNsWvmAfUM7eBthkSPvFruekyDCPNEYhfGqgqt
# qLkoBebXLZCOVybF7wTQaLvse60//3P003icRcCoQYgY4NAqrF7j80o5U7DkeXxc
# B0xvengsaKgiAaV1DKkRbpe98wCqr1AASvm5rAJUYMU+mXmOieV2EelY2jGrenWe
# 9FQpNXYV1NoWBh0WKoFxttoWYAnF705bIWtSZsz08ZfK6WLX4GXNLcPBlgCzfTm1
# sdKYASWdBbH2haaNhPapFhQQBJHKwnVW2iXErImhuPi45W3MVTZ5D9ASshZx69cL
# YY6xAdIa+89Kf/uRrsGOVZfahDuDw+NI183iAyzC8z/QRt2P32LYxP0xrCdqVh+D
# Jo2i4NoE8Uk1usCdbVRuBMBQl/AwpOTq7IMvHGElf65CqzUCAwEAAaOCAUswggFH
# MBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBQPU8s/FmEl/mCJHdO5fOiQrbOU
# 0TAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0T
# AQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBaBgNV
# HR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9w
# cm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsGAQUF
# BwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3Br
# aS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MA0GCSqGSIb3
# DQEBCwUAA4ICAQCjuZmM8ZVNDgp9wHsL4RY8KJ8nLinvxFTphNGCrxaLknkYG5pm
# MhVlX+UB/tSiW8W13W60nggz9u5xwMx7v/1t/Tgm6g2brVyOKI5A7u6/2SIJwkJK
# Fw953K0YIKVT28w9zl8dSJnmRnyR0G86ncWbF6CLQ6A6lBQ9o2mTGVqDr4m35WKA
# nc6YxUUM1y74mbzFFZr63VHsCcOp3pXWnUqAY1rb6Q6NX1b3clncKqLFm0EjKHcQ
# 56grTbwuuB7pMdh/IFCJR01MQzQbDtpEisbOeZUi43YVAAHKqI1EO9bRwg3frCjw
# Abml9MmI4utMW94gWFgvrMxIX+n42RBDIjf3Ot3jkT6gt3XeTTmO9bptgblZimhE
# RdkFRUFpVtkocJeLoGuuzP93uH/Yp032wzRH+XmMgujfZv+vnfllJqxdowoQLx55
# FxLLeTeYfwi/xMSjZO2gNven3U/3KeSCd1kUOFS3AOrwZ0UNOXJeW5JQC6Vfd1Ba
# vFZ6FAta1fMLu3WFvNB+FqeHUaU3ya7rmtxJnzk29DeSqXgGNmVSywBS4NajI5jJ
# IKAA6UhNJlsg8CHYwUOKf5ej8OoQCkbadUxXygAfxCfW2YBbujtI+PoyejRFxWUj
# YFWO5LeTI62UMyqfOEiqugoYjNxmQZla2s4YHVuqIC34R85FQlg9pKQBsDCCBwMw
# ggTroAMCAQICEzMAAABVyAZrOCOXKQkAAAAAAFUwDQYJKoZIhvcNAQELBQAwfTEL
# MAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1v
# bmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEnMCUGA1UEAxMeTWlj
# cm9zb2Z0IE1hcmtldFBsYWNlIFBDQSAyMDExMB4XDTIxMDkwOTIyNDIzMFoXDTMw
# MDkwOTIyNTIzMFowgYcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xMTAvBgNVBAMTKE1pY3Jvc29mdCBNYXJrZXRwbGFjZSBQcm9kdWN0aW9uIENB
# IDIwMTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDHfQ3P+L0El1S6
# JNYAz70y3e1i7EZAYcCDVXde/nQdpOKtVr6H4QkBkROv7HBxY0U8lR9C3bUUZKn6
# CCcN3v3bQuYKu1Ff2G4nIIr8a1cB4iOU8i4YSN7bRr+5LvD5hyCfJHqXrJe5LRRG
# jws5aRAxYuGhQ3ypWPEZYfrIXmmYK+e+udApgxahHUPBqcbI2PT1PpkKDgqR7hyz
# W0CfWzRUwh+YoZpsVvDaEkxcHQe/yGJB5BluYyRm5K9z+YQqBvYJkNUisTE/9OIm
# naZqoujkEuhM5bBV/dNjw7YN37OcBuH0NvlQomLQo+V7PA519HVVE1kRQ8pFad6i
# 4YdRWpj/+1yFskRZ5m7y+dEdGyXAiFeIgaM6O1CFrA1LbMAvyaZpQwBkrT/etC0h
# w4BPmW70zSmSubMoHpx/UUTNo3fMUVqx6r2H1xsc4aXTpPN5IxjkGIQhPN6h3q5J
# C+JOPnsfDRg3Ive2Q22jj3tkNiOXrYpmkILk7v+4XUxDErdc/WLZ3sbF27hug7HS
# VbTCNA46scIqE7ZkgH3M7+8aP3iUBDNcYUWjO1u+P1Q6UUzFdShSbGbKf+Z3xpql
# wdxQq9kuUahACRQLMFjRUfmAqGXUdMXECRaFPTxl6SB/7IAcuK855beqNPcexVEp
# kSZxZJbnqjKWbyTk/GA1abW8zgfH2QIDAQABo4IBbzCCAWswEgYJKwYBBAGCNxUB
# BAUCAwEAATAjBgkrBgEEAYI3FQIEFgQUeBlfau2VIfkwk2K+EoAD6hZ05ccwHQYD
# VR0OBBYEFJ6n+aAjcJ8RxWnjoY0K+vGw9NWAMBkGCSsGAQQBgjcUAgQMHgoAUwB1
# AGIAQwBBMAsGA1UdDwQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMB8GA1UdIwQY
# MBaAFA9Tyz8WYSX+YIkd07l86JCts5TRMFcGA1UdHwRQME4wTKBKoEiGRmh0dHA6
# Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY01hclBDQTIw
# MTFfMjAxMS0wMy0yOC5jcmwwWwYIKwYBBQUHAQEETzBNMEsGCCsGAQUFBzAChj9o
# dHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY01hclBDQTIwMTFf
# MjAxMS0wMy0yOC5jcnQwDQYJKoZIhvcNAQELBQADggIBACY4RaglNFzKOO+3zgaz
# CsgCvXca79D573wDc0DAj6KzBX9m4rHhAZqzBkfSWvanLFilDibWmbGUGbkuH0y2
# 9NEoLVHfY64PXmXcBWEWd1xK4QxyKx2VVDq9P9494Z/vXy9OsifTP8Gt2UkhftAQ
# McvKgGiAHtyRHda8r7oU4cc4ITZnMsgXv6GnMDVuIk+Cq0Eh93rgzKF2rJ1sJcra
# H/kgSkgawBYYdJlXXHTkOrfEPKU82BDT5h8SGsXVt5L1mwRzjVQRLs1FNPkA+Kqy
# z0L+UEXJZWldNtHC79XtYh/ysRov4Yu/wLF+c8Pm15ICn8EYJUL4ZKmk9ZM7ZcaU
# V/2XvBpufWE2rcMnS/dPHWIojQ1FTToqM+Ag2jZZ33fl8rJwnnIF/Ku4OZEN24wQ
# LYsOMHh6WKADxkXJhiYUwBe2vCMHDVLpbCY7CbPpQdtBYHEkto0MFADdyX50sNVg
# TKboPyCxPW6GLiR5R+qqzNRzpYru2pTsM6EodSTgcMbeaDZI7ssnv+NYMyWstE1I
# XQCUywLQohNDo6H7/HNwC8HtdsGd5j0j+WOIEO5PyCbjn5viNWWCUu7Ko6Qx68Nu
# xHf++swe9YQhufh0hzJnixidTRPkBUgYQ6xubG6I5g/2OO1BByOu9/jt5vMTTvct
# q2YWOhUjoOZPe53eYSzjvNydMYIaLzCCGisCAQEwgZ8wgYcxCzAJBgNVBAYTAlVT
# MRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQK
# ExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMTAvBgNVBAMTKE1pY3Jvc29mdCBNYXJr
# ZXRwbGFjZSBQcm9kdWN0aW9uIENBIDIwMTECEzMAAAA6pUx6D+ktjlYAAQAAADow
# DQYJYIZIAWUDBAIBBQCggbAwGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYK
# KwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIDP71VA7
# CLnRYTAIHb/bw/e5PBRBpD/1YAPQGLea4h55MEQGCisGAQQBgjcCAQwxNjA0oBCA
# DgBWAFMAIABDAG8AZABloSCAHmh0dHBzOi8vY29kZS52aXN1YWxzdHVkaW8uY29t
# LzANBgkqhkiG9w0BAQEFAASCAQCPIqPeNotNd+zkagph1h7QvuS7c6gPJevaLO4h
# fB/hvXLNOGXget06qdnFs1tXmvnQx8MmH00O74GLLwFFVm3BSX2XBHbBExN49FnZ
# 5O2iEPftlppPKU5gMLzaTb9BLQM0Z2oqoEm/bKNsZFJSZxzksK5n3oEPGXBMLb94
# TJcVzHvhwE6tuOdaAk4ugJpmJ1a7umsefnNbn6TGlKd41J/c07Kp1BcnTp3QOEu+
# kc7Zaf4/P+U9i0p+yxaqsyEoE0FlwhNgeLWGQuGG2a9qONMfGsSwK0c1H6I+nwQ3
# D4sNqLnF6Wm+rC/MPgBZv/hmQCjZr2J6bhbRgRK8DghucvxaoYIXrTCCF6kGCisG
# AQQBgjcDAwExgheZMIIXlQYJKoZIhvcNAQcCoIIXhjCCF4ICAQMxDzANBglghkgB
# ZQMEAgEFADCCAVoGCyqGSIb3DQEJEAEEoIIBSQSCAUUwggFBAgEBBgorBgEEAYRZ
# CgMBMDEwDQYJYIZIAWUDBAIBBQAEILdfjtS6qlkh1KgVbyoyUIlN1ssMkrTuFcOb
# 47Vg/QoMAgZoo61v7fUYEzIwMjUwOTEwMDcwODQ0LjM0NVowBIACAfSggdmkgdYw
# gdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsT
# JE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMe
# blNoaWVsZCBUU1MgRVNOOjJBMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR+zCCBygwggUQoAMCAQICEzMAAAH5H2eN
# dauk8bEAAQAAAfkwDQYJKoZIhvcNAQELBQAwfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwHhcNMjQwNzI1MTgzMTA5WhcNMjUxMDIyMTgzMTA5WjCB0zELMAkG
# A1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQx
# HjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9z
# b2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBMaW1pdGVkMScwJQYDVQQLEx5uU2hpZWxk
# IFRTUyBFU046MkExQS0wNUUwLUQ5NDcxJTAjBgNVBAMTHE1pY3Jvc29mdCBUaW1l
# LVN0YW1wIFNlcnZpY2UwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0
# PUwffIAdYc1WyUL4IFOP8yl3nksM+1CuE3tZ6oWFF4L3EpdKOhtbVkfMdTxXYE4l
# SJiDt8MnYDEZUbKi9S2AZmDb4Zq4UqTdmOOwtKyp6FgixRCuBf6v9UBNpbz841bL
# qU7IZnBmnF9XYRfioCHqZvaFp0C691tGXVArW18GVHd914IFAb7JvP0kVnjks3am
# zw1zXGvjU3xCLcpUkthfSJsRsCSSxHhtuzMLO9j691KuNbIoCNHpiBiFoFoPETYo
# MnaxBEUUX96ALEqCiB0XdUgmgIT9a7L0y4SDKl5rUd6LuUUa90tBkfkmjZBHm43y
# GIxzxnjtFEm4hYI57IgnVidGKKJulRnvb7Cm/wtOi/TIfoLkdH8Pz4BPi+q0/nsh
# NewP0M86hvy2O2x589xAl5tQ2KrJ/JMvmPn8n7Z34Y8JxcRih5Zn6euxlJ+t3kMc
# zii8KYPeWJ+BifOM6vLiCFBP9y+Z0fAWvrIkamFb8cbwZB35wHjDvAak6EdUlvLj
# iQZUrwzNj2zfYPLVMecmDynvLWwQbP8DXLzhm3qAiwhNhpxweEEqnhw5U2t+hFVT
# HYb/ROvsOTd+kJTy77miWo8/AqBmznuOX6U6tFWxfUBgSYCfILIaupEDOkZfKTUe
# 80gGlI025MFCTsUG+75imLoDtLZXZOPqXNhZUG+4YQIDAQABo4IBSTCCAUUwHQYD
# VR0OBBYEFInto7qclckj16KPNLlCRHZGWeAAMB8GA1UdIwQYMBaAFJ+nFV0AXmJd
# g/Tl0mWnG1M1GelyMF8GA1UdHwRYMFYwVKBSoFCGTmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2lvcHMvY3JsL01pY3Jvc29mdCUyMFRpbWUtU3RhbXAlMjBQQ0El
# MjAyMDEwKDEpLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUGh0dHA6
# Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVGlt
# ZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3J0MAwGA1UdEwEB/wQCMAAwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwDgYDVR0PAQH/BAQDAgeAMA0GCSqGSIb3DQEBCwUA
# A4ICAQBmIAmAVuR/uN+HH+aZmWcZmulp74canFbGzwjv29RvwZCi7nQzWezuLAbY
# Jx2hdqrtWClWQ1/W68iGsZikoIFdD5JonY7QG/C4lHtSyBNoo3SP/J/d+kcPSS0f
# 4SQS4Zez0MEvK3vWK61WTCjD2JCZKTiggrxLwCs0alI7N6671N0mMGOxqya4n7ar
# lOOauAQrI97dMCkCKjxx3D9vVwECaO0ju2k1hXk/JEjcrU2G4OB8SPmTKcYX+6LM
# /U24dLEX9XWSz/a0ISiuKJwziTU8lNMDRMKM1uSmYFywAyXFPMGdayqcEK3135R3
# 1VrcjD0GzhxyuSAGMu2De9gZhqvrXmh9i1T526n4u5TR3bAEMQbWeFJYdo767bLp
# KLcBo0g23+k4wpTqXgBbS4NZQff04cfcSoUe1OyxldoM6O3JGBuowaaR/wojeohU
# FknZdCmeES5FuH4CCmZGf9rjXQOTtW0+Da4LjbZYsLwfwhWT8V6iJJLi8Wh2GdwV
# 60nRkrfrDEBrcWI+AF5tFbJW1nvreoMPPENvSYHocv0cR9Ns37igcKRlrUcqXwHS
# zxGIUEx/9bv47sQ9n7AwfzB2SNntJux1211GBEBGpHwgU9a6tD6yft+0SJ9qiPO4
# IRqFIByrzrKPBB5M831gb1vfhFO6ueSkP7A8ZMHVZxwymwuUzTCCB3EwggVZoAMC
# AQICEzMAAAAVxedrngKbSZkAAAAAABUwDQYJKoZIhvcNAQELBQAwgYgxCzAJBgNV
# BAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4w
# HAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xMjAwBgNVBAMTKU1pY3Jvc29m
# dCBSb290IENlcnRpZmljYXRlIEF1dGhvcml0eSAyMDEwMB4XDTIxMDkzMDE4MjIy
# NVoXDTMwMDkzMDE4MzIyNVowfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDk4aZM57RyIQt5osvXJHm9
# DtWC0/3unAcH0qlsTnXIyjVX9gF/bErg4r25PhdgM/9cT8dm95VTcVrifkpa/rg2
# Z4VGIwy1jRPPdzLAEBjoYH1qUoNEt6aORmsHFPPFdvWGUNzBRMhxXFExN6AKOG6N
# 7dcP2CZTfDlhAnrEqv1yaa8dq6z2Nr41JmTamDu6GnszrYBbfowQHJ1S/rboYiXc
# ag/PXfT+jlPP1uyFVk3v3byNpOORj7I5LFGc6XBpDco2LXCOMcg1KL3jtIckw+DJ
# j361VI/c+gVVmG1oO5pGve2krnopN6zL64NF50ZuyjLVwIYwXE8s4mKyzbnijYjk
# lqwBSru+cakXW2dg3viSkR4dPf0gz3N9QZpGdc3EXzTdEonW/aUgfX782Z5F37Zy
# L9t9X4C626p+Nuw2TPYrbqgSUei/BQOj0XOmTTd0lBw0gg/wEPK3Rxjtp+iZfD9M
# 269ewvPV2HM9Q07BMzlMjgK8QmguEOqEUUbi0b1qGFphAXPKZ6Je1yh2AuIzGHLX
# pyDwwvoSCtdjbwzJNmSLW6CmgyFdXzB0kZSU2LlQ+QuJYfM2BjUYhEfb3BvR/bLU
# HMVr9lxSUV0S2yW6r1AFemzFER1y7435UsSFF5PAPBXbGjfHCBUYP3irRbb1Hode
# 2o+eFnJpxq57t7c+auIurQIDAQABo4IB3TCCAdkwEgYJKwYBBAGCNxUBBAUCAwEA
# ATAjBgkrBgEEAYI3FQIEFgQUKqdS/mTEmr6CkTxGNSnPEP8vBO4wHQYDVR0OBBYE
# FJ+nFV0AXmJdg/Tl0mWnG1M1GelyMFwGA1UdIARVMFMwUQYMKwYBBAGCN0yDfQEB
# MEEwPwYIKwYBBQUHAgEWM2h0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMv
# RG9jcy9SZXBvc2l0b3J5Lmh0bTATBgNVHSUEDDAKBggrBgEFBQcDCDAZBgkrBgEE
# AYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB
# /zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvXzpoYxDBWBgNVHR8ETzBNMEug
# SaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9N
# aWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYIKwYBBQUHAQEETjBMMEoGCCsG
# AQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL2NlcnRzL01pY1Jv
# b0NlckF1dF8yMDEwLTA2LTIzLmNydDANBgkqhkiG9w0BAQsFAAOCAgEAnVV9/Cqt
# 4SwfZwExJFvhnnJL/Klv6lwUtj5OR2R4sQaTlz0xM7U518JxNj/aZGx80HU5bbsP
# MeTCj/ts0aGUGCLu6WZnOlNN3Zi6th542DYunKmCVgADsAW+iehp4LoJ7nvfam++
# Kctu2D9IdQHZGN5tggz1bSNU5HhTdSRXud2f8449xvNo32X2pFaq95W2KFUn0CS9
# QKC/GbYSEhFdPSfgQJY4rPf5KYnDvBewVIVCs/wMnosZiefwC2qBwoEZQhlSdYo2
# wh3DYXMuLGt7bj8sCXgU6ZGyqVvfSaN0DLzskYDSPeZKPmY7T7uG+jIa2Zb0j/aR
# AfbOxnT99kxybxCrdTDFNLB62FD+CljdQDzHVG2dY3RILLFORy3BFARxv2T5JL5z
# bcqOCb2zAVdJVGTZc9d/HltEAY5aGZFrDZ+kKNxnGSgkujhLmm77IVRrakURR6nx
# t67I6IleT53S0Ex2tVdUCbFpAUR+fKFhbHP+CrvsQWY9af3LwUFJfn6Tvsv4O+S3
# Fb+0zj6lMVGEvL8CwYKiexcdFYmNcP7ntdAoGokLjzbaukz5m/8K6TT4JDVnK+AN
# uOaMmdbhIurwJ0I9JZTmdHRbatGePu1+oDEzfbzL6Xu/OHBE0ZDxyKs6ijoIYn/Z
# cGNTTY3ugm2lBRDBcQZqELQdVTNYs6FwZvKhggNWMIICPgIBATCCAQGhgdmkgdYw
# gdMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdS
# ZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLTArBgNVBAsT
# JE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEnMCUGA1UECxMe
# blNoaWVsZCBUU1MgRVNOOjJBMUEtMDVFMC1EOTQ3MSUwIwYDVQQDExxNaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBTZXJ2aWNloiMKAQEwBwYFKw4DAhoDFQCqzlaNY7vNUAqY
# hx3CGqBm/KnpRqCBgzCBgKR+MHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNo
# aW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29y
# cG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEw
# MA0GCSqGSIb3DQEBCwUAAgUA7Gsq2TAiGA8yMDI1MDkwOTIyMzgxN1oYDzIwMjUw
# OTEwMjIzODE3WjB0MDoGCisGAQQBhFkKBAExLDAqMAoCBQDsayrZAgEAMAcCAQAC
# AiQxMAcCAQACAhKBMAoCBQDsbHxZAgEAMDYGCisGAQQBhFkKBAIxKDAmMAwGCisG
# AQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEAAgMBhqAwDQYJKoZIhvcNAQELBQAD
# ggEBALv8CkM6luB/NYgwtqMq7zBM+AaspDvj2QvzUArwsleSm3nKMVfds8y9v6eK
# 2Zl6QC1G9Tg3R+zKrBSk4fuISfd1xbHjT8snCe/6V5Bpc3J5s4HK+DCZkOIILc/D
# nsQsxcLmuS/HEK8+LiTwH0Y5i/k7Mte/nFPv22hQ/QDv7mBhGpUNseWCsWLx1eo6
# lvyb5/51ru+LHYlD1QHL6xK4yQJAWEB5bT99QXzXycVWxSchYu9vBn3ZP5z+X5nd
# LJEv67roMfEdBjYBVlEA/7w9HrmwWWzO2T+0+e5txnFgW1Uclc70JNsprEj7Mq4r
# pw2/hbsVJ/lZ/I0xlCrGfeSTtxQxggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJV
# UzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UE
# ChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGlt
# ZS1TdGFtcCBQQ0EgMjAxMAITMwAAAfkfZ411q6TxsQABAAAB+TANBglghkgBZQME
# AgEFAKCCAUowGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJ
# BDEiBCA76FV5NJQ0LbKVYVmguNkF4K9bFU31YT0ZN2hv/KBpMTCB+gYLKoZIhvcN
# AQkQAi8xgeowgecwgeQwgb0EIDkjjMge8I37ZPrpFQ4sJmtQRV2gqUqXxV4I7lJs
# YtgQMIGYMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAH5
# H2eNdauk8bEAAQAAAfkwIgQgRiEAt05F8qCnRY+2IqhZR4jM1qpnQOrJxOOQ3dbj
# FCgwDQYJKoZIhvcNAQELBQAEggIAbU/QXOWAP3Yq1oS9rjGj8YSzz6nlMYGHv3hl
# rCTXlS+HnxJYjcXpSYlnp0VsN64VksZq6KQV8r/PgSNEQUZ7P75076R/A3oUhAWH
# GJ5VOzeTBLeMR8lo4rCQ9MT3SdLaujW1jRiTeeh9oNnTcqGeFZ0fJWTkx7gcgX3A
# kR9xnh3spQBZdjW4zWkmpo8FSFgZ8rk79x/8AEDE+Lyat4KyRY8qrIkZ2aG5FxnY
# mE/hC6mYbeNEPxJpVU5IBYqstLe2vmgZIvoCLrMRjwJb33zJoHedmn+qlioj4QzU
# V6VdpbgVz8ikr+ADRaL4V9pFgIvj5oV1BDgdOoX8hQgI4cZMCtqsxKLDp4q9HEQf
# ZFxx2shTUKBybAPKc051T0oioJ4snfqoz9yR6H5x9tWbcwz2VxbKlrc5Syr/prU0
# Pkk0qGTvHI3Mp47oqoUsDBNGd/GIY9G6Bv51p4G/t4cYhjmdQbDTAX9gIMdadgno
# wJojDR7U8Zrd0NowOd8ANvtkJe/LrDzbkyYzgRknUJ44XawchsNdXcN9u26ET1tw
# tmQxsyeuvu1GCJhkSJMJJj6ZHmxddAhj5Ca0jaADaSV1Rl7WJLtdTzZfvCZ5vGuM
# QTIzxB2MUbSa2KGNx/iIu6x2OuFLlvNhwMbZr/d0swPmGJZOyaBhbFwQ5WA3thHR
# ZiqYAaM=
# SIG # End signature block
