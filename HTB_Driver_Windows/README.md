
---

# Machine info:

![logo](./screenshots/logo.png)

## HTB Driver - Windows

## Difficulty - Easy

---

Driver is an easy Windows machine that focuses on printer exploitation. Enumeration of the machine reveals that a web server is listening on port 80, along with
SMB on port 445 and WinRM on port 5985. Navigation to the website reveals that it&amp;amp;amp;#039;s protected using basic HTTP authentication. While trying common
credentials the `admin:admin` credential is accepted and we are able to visit the webpage. The webpage provides a feature to upload printer firmwares on an SMB share
for a remote team to test and verify. Uploading a Shell Command File that contains a command to fetch a remote file from our local machine, leads to the NTLM hash of
the user `tony` relayed back to us. Cracking the captured hash to retrieve a plaintext password we are able login as `tony`, using WinRM. Then, switching over to a
meterpreter session it is discovered that the machine is vulnerable to a local privilege exploit that abuses a specific printer driver that is present on the remote machine.
Using the exploit we can get a session as `NT AUTHORITY\SYSTEM`.

---

> Skill required:

- Based Web Enumeration
- Based Windows CLI

> Skill Learned:

