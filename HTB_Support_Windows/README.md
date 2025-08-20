
---
<div align="center">

<img src="./screenshots/support_icon.png" alt="logo" width="120"/>

# HTB: Support (Windows)

### 📊 Difficulty: **Easy**
### 📁 Category: Active Directory / Privilege Escalation

</div>

---

<p align="center">
🔎 During the attack, reconnaissance of the target system was conducted, which led to the discovery of a non-standard network share containing a set of tools for the `Windows infrastructure`,
intended for **system administrators** and **technical support**. Among these tools, an archive with a custom (unofficial) program, `UserInfo.exe`, compiled as a `.NET` assembly, was found.
After decompiling this program, a password for an `LDAP service account` was recovered from the source code, which was then used to enumerate `Active Directory` objects. During the enumeration,
the `support user account` was discovered. This account belonged to the `Remote Management Users` group and contained a `password` in its info field, which provided `initial access` to the system.
Further enumeration within the `Windows environment` revealed that the support user was a member of a non-standard group, `Shared Account Operators`, which had `GenericAll` privileges over the
Domain Controller `dc.support.htb`. By resetting the `DC$` account password, the `DCSync` technique was successfully executed to obtain the `NTLM hash` of the Administrator account, resulting in a
complete compromise of the system.
</p>

---

> 💡 **Skills Required**
- Windows CLI
- Active Directory Enumeration

> 🛠️ **Skills Learned**
- DCSync exploitation
- reverse engineering
