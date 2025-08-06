$get_domainDN = (Get-ADDomain).DistinguishedName
$get_domainObject = [ADSI]"LDAP://$domainDN"
$get_ACL = $domainObject.ObjectSecurity.Access

foreach ($ace in $get_ACL) {
    if ($ace.IdentityReference -eq "administrator\ethan") {
        $ace
    }
}
