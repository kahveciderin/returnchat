from hashlib import sha256
import socket
h = sha256()

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 27735        # The port used by the server


uname = "kahve"
pwd = "123456"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    h.update(pwd.encode("utf8"))

    s.send("req_register {} {}".format(uname, h.hexdigest()).encode('utf-8'))
    resp = s.recv(0xFFFFFFFF)
    if(resp[0:13] == "uname_present".encode("utf8")):
        print("username exists")