import asyncio
import socket
from random import randint

import sqlite3
from math import ceil, log
import base64

from decimal import Decimal

import time, datetime
from hashlib import sha256


keylen = 64
pwdsaltlen = 128


db = None
cur = None
import atexit
def exit_handler():
    print('Terminating server...')
    db.close()

atexit.register(exit_handler)


def benc(strg):
    return base64.b64encode(strg.encode("utf8")).decode("ascii")

def bdec(strg):
    return base64.b64decode(strg.encode("ascii")).decode("utf8")
def chnt(strg):
    return str(int(strg))

def chnx(strg):
    return str(int(strg, 16))
def create_connection(db_file):

    conn = None
    try:
        conn = sqlite3.connect(db_file)
        print("SqLite Version:", sqlite3.version)
        conn.execute("CREATE TABLE IF NOT EXISTS users ( userid INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL, password TEXT NOT NULL, key TEXT NOT NULL);")
        conn.execute("CREATE TABLE IF NOT EXISTS messages ( msgid INTEGER PRIMARY KEY AUTOINCREMENT, frusr INTEGER NOT NULL, tousr INTEGER NOT NULL, msg TEXT NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP);")
    except sqlite3.Error as e:
        print(e)
        exit()
    return conn


async def handle_client(reader, writer):
    request = None
    uidofsock = None
    saltofsock = None
    while request != 'quit':

        

        try:
            request = (await reader.read(0xFFFF)).decode('utf8').strip()
        except:
            #print("client disconnected")
            return
        response = "illegal_operation".encode('utf8')
        cmd = request.split()
        if(len(cmd) > 0):
            if(cmd[0] == "req_login"):
                salta = ""
                for ig in range(pwdsaltlen):
                    salta += chr(randint(0x20, 0x7E))
                response = salta.encode("utf8")
                saltofsock = salta
                #print(salta)
            elif(cmd[0] == "req_confirm"):
                if(len(cmd) == 3):
                    # print(saltofsock)
                    if(saltofsock != None):
                        
                        cur.execute("SELECT password FROM users WHERE userid = '{}'".format(chnt(cmd[1])))
                        selpwd = cur.fetchall()
                        
                        if(len(selpwd)):
                            h = sha256()
                            
                            h.update((bdec(selpwd[0][0]) + saltofsock).encode("utf8"))
                            if(h.hexdigest() == cmd[2]):
                                uidofsock = chnt(cmd[1])
                                response = "done_login".encode("utf8")
            elif(cmd[0] == "req_key"):
                if(uidofsock != None):
                    cur.execute("SELECT key FROM users WHERE userid = '{}'".format(uidofsock))
                    keysel = cur.fetchall()
                    if(len(keysel)):
                        response = bytearray()
                        for i in range(keylen):
                            response.append(randint(0x00, 0xFF))
                        db.execute("UPDATE users SET key='{}' WHERE userid = '{}'".format(int.from_bytes(response, byteorder='big', signed=False), uidofsock))
                        db.commit()
                        # response = keysel[0][0].encode("utf8")
                        # print(hex(int(keysel[0][0])))
                        # print(hex(int.from_bytes(response, 'big')))
            elif(cmd[0] == "req_register"):
                if(len(cmd) == 3):
                    key = bytearray()
                    for i in range(keylen):
                        key.append(randint(0x00, 0xFF))
                    cur.execute("SELECT username FROM users WHERE username = '{}'".format(benc(cmd[1])))
                    if(len(cur.fetchall())):
                        response = "uname_present {}".format(cmd[1]).encode('utf8')
                    else:
                        db.execute("INSERT INTO users (username, password, key) VALUES ('{}', '{}', '{}')".format(benc(cmd[1]), benc(cmd[2]), int.from_bytes(key, byteorder='big', signed=False)))
                        db.commit()
                        response = key

            elif(cmd[0] == "snd_msg"):
                if(len(cmd) == 3):
                    if(uidofsock != None):
                        cur.execute("SELECT key FROM users WHERE userid = '{}'".format(uidofsock))
                        keysel = cur.fetchall()
                        if(len(keysel)):
                            response = "MSG_SNT".encode("utf8")
                            msgenc = " ".join(cmd[2:])
                            msgenc = int(msgenc, 16)
                            
                            msgenc = msgenc.to_bytes(ceil(ceil(log(msgenc+1)/log(16)) / 2), 'big')
                            
                            key = int(keysel[0][0])
                            # print(hex(key))
                            # print(hex(int.from_bytes(msgenc, 'big')))
                            i = 0
                            decoded = bytearray()
                            
                            for char in msgenc:
                                # print(char)
                                decoded += ((char - ((key & (0xFF * (1 << int(((i) % ceil(log(key+1)/log(16)) / 2) * 8)))) >> (int(((i) % ceil(log(key+1)/log(16)) / 2) * 8)))) % 0x100).to_bytes(1, 'big')
                                i += 1
                            # print(decoded)
                            
                            # print("INSERT INTO messages (frusr, tousr, msg) VALUES ({}, {}, '{}')".format(uidofsock, chnt(cmd[1]), hex(int.from_bytes(decoded, 'big'))[2:]))
                            db.execute("INSERT INTO messages (frusr, tousr, msg) VALUES ({}, {}, '{}')".format(uidofsock, chnt(cmd[1]), hex(int.from_bytes(decoded, 'big'))[2:]))
                            db.commit()
            elif(cmd[0] == "req_msg"):
                if(uidofsock != None):
                    cur.execute("SELECT key FROM users WHERE userid = '{}'".format(uidofsock))
                    keysel = cur.fetchall()
                   
                    if(len(keysel)):
                        cur.execute("SELECT * FROM messages WHERE tousr = '{}'".format(uidofsock))
                        unrdmsgs = cur.fetchall()
                        response = ""
                        key = int(keysel[0][0])
                        # print(type(key))
                        for msgher in unrdmsgs:
                            #response += (repr(msgher) + "\n").encode('utf8')
                            msgid = hex(int(msgher[0]))[2:]
                            frusr = hex(int(msgher[1]))[2:]
                            msgcont = base64.b64encode(int(msgher[3], 16).to_bytes(ceil(log(int(msgher[3], 16)+1)/log(16)), 'big')).decode('ascii')

                            timestamp = int(time.mktime(datetime.datetime.strptime(msgher[4], "%Y-%m-%d %H:%M:%S").timetuple()))
                            response += (msgid + "," + frusr + "," + msgcont + "," + str(timestamp) + "\n")

                        i = 0
                        result = bytearray()
                        for char in response.encode("utf-8"):
                            result += ((char + ((key & (0xFF * (1 << int(((i) % ceil(log(key+1)/log(16)) / 2) * 8))))
                                                >> (int(((i) % ceil(log(key+1)/log(16)) / 2) * 8)))) % 0x100).to_bytes(1, 'big')
                            i += 1
                        response = "msg_resp\n".encode("utf8") + result
                        db.execute("DELETE FROM messages WHERE tousr={}".format(uidofsock))
                        db.commit()

            elif(cmd[0] == "req_whois"):
                if(len(cmd) > 1):
                    query = "SELECT username FROM users WHERE userid IN ("
                    for uid in cmd[1:]:
                        query += str(int(uid)) + ","
                    query = query[0:len(query) - 1]
                    query += ")"

                    cur.execute(query)
                    namsel = cur.fetchall()
                    response = "whois_resp\n"
                    for nam in namsel:
                        response += bdec(nam[0]) + "\n"
                    

                    response = response.encode("utf8")
            elif(cmd[0] == "req_whoami"):
                if(len(cmd) > 1):
                    query = "SELECT userid FROM users WHERE username IN ("
                    for uid in cmd[1:]:
                        query += "'" + benc(uid) + "',"
                    query = query[0:len(query) - 1]
                    query += ")"

                    cur.execute(query)
                    namsel = cur.fetchall()
                    response = "whoami_resp\n"
                    for nam in namsel:
                        response += str(nam[0]) + "\n"
                    
                    response = response.encode("utf8")
            elif(cmd[0] == "req_key_safe"):
                if(uidofsock != None):
                    cur.execute("SELECT password FROM users WHERE userid = '{}'".format(uidofsock))
                    pwdsel = cur.fetchall()
                    if(len(pwdsel)):
                        userpasswd = int.from_bytes(bdec(pwdsel[0][0]).encode("utf8"), 'big')
                        response = bytearray()
                        for i in range(keylen):
                            response.append(randint(0x00, 0xFF))


                        db.execute("UPDATE users SET key='{}' WHERE userid = '{}'".format(int.from_bytes(response, byteorder='big', signed=False), uidofsock))
                        db.commit()
                        
                        # print("key", int.from_bytes(response, 'big'))
                        # print("keyraw", response)
                        
                        response = int.from_bytes(response, 'big') + (userpasswd ** 2)

                        # print("encdecdeckey", response - userpasswd)
                        # print("enckey", hex(response))
                        # print("pwd", hex(userpasswd))
                        
                        response = response.to_bytes(ceil(ceil(log(response+1)/log(16)) / 2), 'big')
        # if(response == "illegal_operation".encode('utf8')):

            # print(request)
        # print(response)

        # print(request)
        # print(response)
        # print("##############################################")
        writer.write(response)
        try:
            await writer.drain()
        except:
            # print("client disconnected")
            return
    writer.close()


async def run_server():
    while True:
        client, _ = await loop.sock_accept(server)
        loop.create_task(handle_client(client))


db = create_connection("userdata.db")
cur = db.cursor()
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', 15555))
server.listen(8)
server.setblocking(False)
loop = asyncio.get_event_loop()
loop.create_task(asyncio.start_server(handle_client, '0.0.0.0', 27735))
loop.run_forever()
