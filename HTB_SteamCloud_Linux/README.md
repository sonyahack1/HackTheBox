
---

# Machine info:

![logo](./screenshots/logo.png)

## HTB SteamCloud - Linux

## Difficulty - Easy

---

SteamCloud is an easy difficulty machine. The port scan reveals that it has a bunch of Kubernetes specific ports open.
We cannot not enumerate the Kubernetes API because it requires authentication. Now, as Kubelet allows anonymous access,
we can extract a list of all the pods from the K8s cluster by enumerating the Kubelet service. Furthermore, we can get
into one of the pods and obtain the keys necessary to authenticate into the Kubernetes API. We can now create and spawn
a malicious pod and then use Kubectl to run commands within the pod to read the root flag.

---

> Skill required:

- Based Web Enumeration
- Kubernetes Enumeration
- Based Linux CLI
- Understanding the basic principles of `containerization` and `virtualization`

> Skill Learned:

- Advanced web knowledge (websocat,curl etc.)
- Exploitation of `Kubelet API`
