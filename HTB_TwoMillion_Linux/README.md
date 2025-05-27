
# Machine info:

![logo](./screenshots/logo.png)

## HTB TwoMillion - Linux

## Difficulty - Easy

---

TwoMillion is an Easy difficulty Linux box that was released to celebrate reaching 2 million users on HackTheBox.
The box features an old version of the HackTheBox platform that includes the old hackable invite code. After hacking
the invite code an account can be created on the platform. The account can be used to enumerate various API endpoints,
one of which can be used to elevate the user to an Administrator. With administrative access the user can perform a command
injection in the admin VPN generation endpoint thus gaining a system shell. An .env file is found to contain database
credentials and owed to password re-use the attackers can login as user admin on the box. The system kernel is found to
be outdated and it's can be used to gain a root shell.

---


> Skill required:

- Api enumeration
- Linux command line

> Skill Learned:

- Command Injection into Api Endpoints
- Exploitation of a vulnerable Linux Kernel


