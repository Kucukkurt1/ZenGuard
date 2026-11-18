rule benign_static_marker
{
    meta:
        description = "Harmless static marker used as a medium-severity example"
        author = "ZenGuard"
        severity = "medium"

    strings:
        $marker = "ZENG_BENIGN_STATIC_MARKER"

    condition:
        $marker
}
