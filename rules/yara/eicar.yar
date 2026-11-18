rule eicar
{
    meta:
        description = "EICAR standard anti-malware test string (harmless)"
        author = "ZenGuard"
        severity = "critical"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}
