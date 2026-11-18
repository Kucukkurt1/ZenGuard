rule fixture_keylogger
{
    meta:
        description = "ZenGuard drill. Text mentions key-reading APIs. Not a working keylogger."
        author = "ZenGuard"
        severity = "critical"

    strings:
        $mark = "ZENG_FIXTURE_KEYLOGGER"
        $api1 = "GetAsyncKeyState"
        $api2 = "SetWindowsHookEx"

    condition:
        $mark and $api1 and $api2
}

rule fixture_ransom_note
{
    meta:
        description = "ZenGuard drill. Ransom-note wording only. Does not encrypt files."
        author = "ZenGuard"
        severity = "critical"

    strings:
        $mark = "ZENG_FIXTURE_RANSOM"
        $locked = "dosyalariniz sifrelendi" nocase
        $pay = "bitcoin" nocase

    condition:
        $mark and $locked and $pay
}
