---
<div align="center">

<img src="./screenshots/vintage_icon.png" alt="logo" width="120"/>

# HTB: Vintage

### 📊 Difficulty: **Hard**
### 📁 Category: Windows / Active Directory

</div>

---

<p align="center">
🔎 During the compromise of the `dc01.vintage.htb` system, a series of attacks were carried out based on misconfigured object permissions within the `Active Directory` environment. Starting with a low-privileged user account `P.Rosa`, reconnaissance was performed, revealing the presence of the `Pre-Windows 2000 Compatible Access` group, which included the host `fs01$` as a member, using a predictable (`username = password`) credential configuration. With access to `fs01$`, and leveraging the `ReadGMSAPassword` privilege, the `NTLM hash` of the managed service account `gmsa01$` was extracted from its `msDS-ManagedPassword` attribute. Using the `AddSelf` permission, the `gmsa01$` account was added to the `ServiceManagers` group, which had `GenericAll` privileges over three service accounts. Leveraging this, the `svc_sql` account was modified by reactivating it and assigning a `SPN`. This setup enabled a `Kerberoasting` attack, resulting in the extraction of a `Kerberos TGS hash`, which was successfully cracked to reveal the password for the `C.Neri` user account, providing `Initial Access` to the system via the `WinRM`.
</p>

<p align="center">
Further enumeration revealed saved credentials for the user `C.Neri_adm` via the `cmdkey` utility. This account was a member of the `DelegatedAdmins` group. Using `svc_sql`, and leveraging the privileges of `C.Neri_adm`, a `Resource-Based Constrained Delegation` attack was carried out. This allowed the attacker to `impersonate` the domain administrator account `L.BIANCHI_ADM`, ultimately leading to `full domain compromise`.
</p>
---

> 💡 **Skills Required**
- Active Directory Enumeration
- Skill in working with the Kerberos protocol

> 🛠️ **Skills Learned**
- `Kerberoasing` attack
- `RBCD` Exploitation
