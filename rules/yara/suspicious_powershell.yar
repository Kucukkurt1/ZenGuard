rule suspicious_powershell
{
    meta:
        description = "PowerShell with obfuscation or execution bypass indicators"
        author = "ZenGuard"
        severity = "high"

    strings:
        $ps = "powershell" nocase
        $ps_iex = "powershell.exe -" nocase
        $enc = "-enc" nocase
        $encoded = "-encodedcommand" nocase
        $bypass = "-ep bypass" nocase
        $bypass2 = "-executionpolicy bypass" nocase
        $hidden = "-windowstyle hidden" nocase
        $iex = "Invoke-Expression" nocase
        $download = "DownloadString" nocase
        $iwr = "Invoke-WebRequest" nocase

    condition:
        any of ($ps, $ps_iex) and (
            any of ($enc, $encoded, $bypass, $bypass2, $hidden, $iex, $download, $iwr)
        )
}
