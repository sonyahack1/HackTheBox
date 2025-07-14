
---

# Machine info:

![logo](./screenshots/cap_icon.png)

## HTB Cap - Linux

## Difficulty - Easy

---

Cap is an easy difficulty Linux machine running an HTTP server that performs administrative functions including performing network captures.
Improper controls result in Insecure Direct Object Reference (IDOR) giving access to another user's capture. The capture contains plaintext
credentials and can be used to gain foothold. A Linux capability is then leveraged to escalate to root.

---

> Skill required:

- knowledge of web vulnerabilities
- Linux enumeration

> Skill Learned:

- Exploitation of `IDOR` vulnerability
- Exploitation of `cap_setuid` capability
