$target = "CN=Michael Williams,CN=Users,DC=administrator,DC=htb"
$entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$target")
$ACL = $entry.ObjectSecurity.Access

foreach ($ace in $ACL) {
    if ($ace.IdentityReference -eq "administrator\olivia") {
        $ace
    }
}
