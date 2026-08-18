rule AllanSecurity_EICAR_Test
{
    meta:
        description = "Arquivo de teste padrão EICAR; não é malware real"
        category = "antivirus-test"
        severity = "critical"
    strings:
        $eicar = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $eicar
}
