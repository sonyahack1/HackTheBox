
---

# Machine info:

![logo](./screenshots/sau_icon.png)

## HTB Sau - Linux

## Difficulty - Easy

---

`Sau` is an Easy Difficulty Linux machine that features a `Request Baskets` instance that is vulnerable to Server-Side Request Forgery (SSRF).
Leveraging the vulnerability we are to gain access to a `Maltrail` instance that is vulnerable to Unauthenticated OS Command Injection, which 
allows us to gain a reverse shell on the machine as `puma`. A `sudo` misconfiguration is then exploited to gain a `root` shell.

---

> Skill required:

- Basic Web Knowledge
- Basic understanding vulnerabilities `SSRF` and `Command Injection`
- Basic Linux knowledge

> Skill Learned:

- `OS Command Injection` exploitation
- `SSRF` exploitation
- Exploitation of `sudo configuration`
- Writing exploit

