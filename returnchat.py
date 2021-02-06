# import all the required modules 
import socket 
import threading 
from tkinter import *
from tkinter import font 
from tkinter import ttk 


from hashlib import sha256

import time
import emoji

import sys, select, base64
import os as opsys  
from math import ceil, log
from random import randint
HOST = 'kahveciderin.com'  # The server's hostname or IP address
PORT = 27735        # The port used by the server



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)




# GUI class for the chat 
class GUI: 

    key = None

    uid = None


    
    # constructor method 
    def __init__(self): 
        def on_closing():
            opsys._exit(0)
        # chat window which is currently hidden 
        self.Window = Tk() 
        self.Window.withdraw() 
        self.Window.protocol("WM_DELETE_WINDOW", on_closing)

        

        # login window 
        self.login = Toplevel() 

        self.login.protocol("WM_DELETE_WINDOW", on_closing)
        # set the title 
        self.login.title("Login") 
        self.login.resizable(width = False, 
                            height = False) 
        self.login.configure(width = 400, 
                            height = 300) 
        # create a Label 
        self.pls = Label(self.login, 
                    text = "Please login to continue", 
                    justify = CENTER, 
                    font = "Helvetica 14 bold") 
        
        self.pls.place(relheight = 0.15, 
                    relx = 0.2, 
                    rely = 0.07) 

        # create a Label 
        self.labelServer = Label(self.login, 
                            text = "Server: ", 
                            font = "Helvetica 12") 
        
        self.labelServer.place(relheight = 0.2, 
                            relx = 0.1, 
                            rely = 0.2) 
        self.entryServer = Entry(self.login, 
                            font = "Helvetica 14") 
        
        self.entryServer.place(relwidth = 0.4, 
                            relheight = 0.12, 
                            relx = 0.35, 
                            rely = 0.2) 

        
        # create a Label 
        self.labelName = Label(self.login, 
                            text = "Name: ", 
                            font = "Helvetica 12") 
        
        self.labelName.place(relheight = 0.2, 
                            relx = 0.1, 
                            rely = 0.4) 
        
        # create a entry box for 
        # tyoing the message 
        self.entryName = Entry(self.login, 
                            font = "Helvetica 14") 
        
        self.entryName.place(relwidth = 0.4, 
                            relheight = 0.12, 
                            relx = 0.35, 
                            rely = 0.4) 
        

                # create a Label 
        self.labelPwd = Label(self.login, 
                            text = "Pass: ", 
                            font = "Helvetica 12") 
        
        self.labelPwd.place(relheight = 0.2, 
                            relx = 0.1, 
                            rely = 0.6) 
        
        # create a entry box for 
        # tyoing the message 
        self.entryPwd = Entry(self.login, 
                            font = "Helvetica 14") 
        
        self.entryPwd.place(relwidth = 0.4, 
                            relheight = 0.12, 
                            relx = 0.35, 
                            rely = 0.6) 
        # set the focus of the curser 
        self.entryName.focus() 
        
        # create a Continue Button 
        # along with action 
        self.go = Button(self.login, 
                        text = "CONTINUE", 
                        font = "Helvetica 14 bold", 
                        command = lambda: self.goAhead(self.entryName.get(), self.entryPwd.get(), self.entryServer.get())) 

        self.entryServer.insert(0,"kahveciderin.com")
        # self.entryName.insert(0,"kahve")
        # self.entryPwd.insert(0,"123456")

        self.go.place(relx = 0.4, 
                    rely = 0.85) 
        self.Window.mainloop() 

    def goAhead(self, name, passwd, server): 

        
        global uid
        global key

        h = sha256()
        h.update(passwd.encode("utf8"))

        pwd = h.hexdigest()
        HOST = server
        

        s.connect((HOST, PORT))
        self.login.destroy() 
        self.layout(name) 

        s.send("req_whoami {}".format(name).encode("utf8"))
        print("req_whoami {}".format(name))
        dat = s.recv(0xFFFFFFFF)
        if(dat == "whoami_resp\n".encode("utf8")):
            exit()
        uid = int(dat.decode("utf8").split("\n")[1].strip()) #We know our userid 
        
        time.sleep(0.1)
        s.send("req_login".encode("utf8"))
        print("req_login")
        salt = s.recv(0xFFFFFFFF).decode("utf8")

        print(salt)
        print((pwd + salt))
        h = sha256()
        h.update((pwd + salt).encode("utf8"))
        sndsaltedpwd = h.hexdigest()

        time.sleep(0.1)
        s.send("req_confirm {} {}".format(uid, sndsaltedpwd).encode("utf8"))
        print("req_confirm {} {}".format(uid, sndsaltedpwd).encode("utf8"))
        dat = s.recv(0xFFFFFFFF)
        
        print(dat)
        if(dat != "done_login".encode("utf8")):
            exit()

        # time.sleep(0.1)
        # s.send("req_key".encode("utf8"))
        # print("req_key")
        # keydat = s.recv(0xFFFFFFFF)
        # key = int.from_bytes(keydat,'big')

        # print(hex(key))
        # print(keydat)



        time.sleep(0.1)
        s.send("req_key_safe".encode("utf8"))
        print("req_key_safe")
        keydat = s.recv(0xFFFFFFFF)
        print("keydat", hex(int.from_bytes(keydat, 'big')))       #The key is encrypted with our password. Decrypt it

        userpasswd = int.from_bytes(pwd.encode("utf8"), 'big')
        

        key = int.from_bytes(keydat,'big') - (userpasswd ** 2)
        print("key", key)
        print("pwd", hex(userpasswd))
        # the thread to receive messages 
        rcv = threading.Thread(target=self.receive) 
        rcv.start() 

    # The main layout of the chat 
    def layout(self,name): 
        
        self.name = name 
        # to show chat window 
        self.Window.deiconify() 
        self.Window.title("CHATROOM") 
        self.Window.resizable(width = False, 
                            height = False) 
        self.Window.configure(width = 470, 
                            height = 550, 
                            bg = "#17202A") 
        self.labelHead = Label(self.Window, 
                            bg = "#17202A", 
                            fg = "#EAECEE", 
                            text = self.name , 
                            font = "Helvetica 13 bold", 
                            pady = 5) 
        
        self.labelHead.place(relwidth = 1) 
        self.line = Label(self.Window, 
                        width = 450, 
                        bg = "#ABB2B9") 
        
        self.line.place(relwidth = 1, 
                        rely = 0.07, 
                        relheight = 0.012) 
        
        self.textCons = Text(self.Window, 
                            width = 20, 
                            height = 2, 
                            bg = "#17202A", 
                            fg = "#EAECEE", 
                            font = "Helvetica 14", 
                            padx = 5, 
                            pady = 5) 
        
        self.textCons.place(relheight = 0.745, 
                            relwidth = 1, 
                            rely = 0.08) 
        
        self.labelBottom = Label(self.Window, 
                                bg = "#ABB2B9", 
                                height = 80) 
        
        self.labelBottom.place(relwidth = 1, 
                            rely = 0.825) 
        
        self.entryMsg = Entry(self.labelBottom, 
                            bg = "#2C3E50", 
                            fg = "#EAECEE", 
                            font = "Helvetica 13") 
        

        self.entryUsr = Entry(self.labelBottom, 
                            bg = "#2C3E50", 
                            fg = "#EAECEE", 
                            font = "Helvetica 13") 


        self.textCons.tag_configure("left", justify='left') 
        self.textCons.tag_configure("right", justify='right')

        self.textCons.tag_add("left", 1.0, "end")
        # place the given widget 
        # into the gui window 
        self.entryMsg.place(relwidth = 0.54, 
                            relheight = 0.06, 
                            rely = 0.008, 
                            relx = 0.211) 
        
        self.entryUsr.place(relwidth = 0.2, 
                            relheight = 0.06, 
                            rely = 0.008, 
                            relx = 0.011) 
        self.entryMsg.focus() 
        
        # create a Send Button 
        self.buttonMsg = Button(self.labelBottom, 
                                text = "Send", 
                                font = "Helvetica 10 bold", 
                                width = 20, 
                                bg = "#ABB2B9", 
                                command = lambda : self.sendButton(self.entryMsg.get(), self.entryUsr.get())) 
        
        self.buttonMsg.place(relx = 0.77, 
                            rely = 0.008, 
                            relheight = 0.06, 
                            relwidth = 0.22) 
        
        self.textCons.config(cursor = "arrow") 
        
        # create a scroll bar 
        scrollbar = Scrollbar(self.textCons) 
        
        # place the scroll bar 
        # into the gui window 
        scrollbar.place(relheight = 1, 
                        relx = 0.974) 
        
        scrollbar.config(command = self.textCons.yview) 
        
        self.textCons.config(state = DISABLED) 

    # function to basically start the thread for sending messages 
    def sendButton(self, msg, usr): 
        self.textCons.config(state = DISABLED) 
        self.msg=msg 
        self.usrtosend=usr 
        self.entryMsg.delete(0, END) 
        snd= threading.Thread(target = self.sendMessage) 
        snd.start() 

    # function to receive messages 
    def receive(self):
        while True: 
            try: 
                s.send("req_msg".encode("utf8"))
                data = s.recv(0xFFFFFFFF) 

                
                if(data == "msg_resp\n".encode("utf8")):
                    #print("no new messages")
                    pass
                elif(data == "MSG_SNT".encode("utf8")):
                    #print("no new messages")
                    pass
                elif(data == "illegal_operation".encode("utf8")):
                    #print("no new messages")
                    exit()
                elif(data[0:9] == "msg_resp\n".encode("utf8")):

                    print(data)
                    data = data[9:]
                    uniquids = []
                    print(data)
                    i = 0
                    finresult = bytearray()
                    for char in data:
                        finresult += ((char - ((key & (0xFF * (1 << int(((i) % ceil(log(key+1)/log(16)) / 2) * 8))))
                                            >> (int(((i) % ceil(log(key+1)/log(16)) / 2) * 8)))) % 0x100).to_bytes(1, 'big')
                        i += 1
                    messages = finresult.decode("utf8").split("\n")

                    mesgstoprint = []
                    for mesg in messages:
                        ufldat = mesg.split(",")
                        if(len(ufldat) != 4):
                            break
                        msgid = ufldat[0]
                        frusr = ufldat[1]
                        mesgcont = base64.b64decode(ufldat[2].encode("ascii")).decode("utf8")
                        tstamp = ufldat[3]
                        if(frusr not in uniquids):
                            uniquids.append(frusr)
                        msgtoprint = ">>__uuidunk__" + frusr+ ": "+ mesgcont
                        print(msgtoprint)
                        mesgstoprint.append(emoji.demojize(msgtoprint.replace("\x00", "")))
                
                    printthis = "\n".join(mesgstoprint)
                    
                    s.send(("req_whois " + " ".join(uniquids)).encode("utf8"))
                    uiddata = s.recv(0xFFFFFFFF).decode("utf8")
                    while(uiddata[0:11] != "whois_resp\n"):
                        print(uiddata[0:11])
                        uiddata = s.recv(0xFFFFFFFF).decode("utf8")
                    uiddata = uiddata[11:].split("\n")
                    uidid = 0
                    for uidher in uniquids:
                        printthis = printthis.replace("__uuidunk__" + str(uidher), uiddata[uidid])
                        uidid += 1
                    # insert messages to text box 
                    self.textCons.config(state = NORMAL) 
                    self.textCons.insert(END, printthis) 
                        
                    self.textCons.config(state = DISABLED) 
                    self.textCons.see(END) 
                    
                else:
                    print(data)
            
                time.sleep(0.3)
            except Exception as e: 
                # an error will be printed on the command line or console if there's an error 
                print("An error occured!") 
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(exc_type, fname, exc_tb.tb_lineno) 
                opsys._exit(0)
        
    # function to send messages 
    def sendMessage(self): 
        self.textCons.config(state=DISABLED) 
        while True: 
            message = (f"{self.msg}") 
            s.send("req_whoami {}".format(self.usrtosend).encode("utf8"))


            hhhjjj = s.recv(0xFFFFFFFF).decode("utf8").strip()

            while(hhhjjj[0:12] != 'whoami_resp\n'):
                hhhjjj = s.recv(0xFFFFFFFF).decode("utf8").strip()
            if(hhhjjj == 'whoami_resp\n'):
                print("No such user exists: {}".format(self.usrtosend))

                # insert messages to text box 
                self.textCons.config(state = NORMAL) 
                self.textCons.insert(END, "No such user exists: {}".format(self.usrtosend) + "\n")                     
                self.textCons.config(state = DISABLED) 
                self.textCons.see(END) 
            elif(hhhjjj == "illegal_operation"):
                print("Enter a username to send")

                # insert messages to text box 
                self.textCons.config(state = NORMAL) 
                self.textCons.insert(END, "Enter a username to send" + "\n")                     
                self.textCons.config(state = DISABLED) 
                self.textCons.see(END) 
            else:
                unamid = int(hhhjjj.split("\n")[1].strip())
                i = 0
                result = bytearray()
                for char in message.encode("utf-8"):
                    a = ((char + ((key & (0xFF * (1 << int(((i) % ceil(log(key+1)/log(16)) / 2) * 8)))) >> (int(((i) % ceil(log(key+1)/log(16)) / 2) * 8)))) % 0x100).to_bytes(1, 'big')
                    result += a
                    i+=1
                s.send("snd_msg {} {}".format(unamid, hex(int.from_bytes(result,'big'))[2:]).encode('utf-8'))
                print("snd_msg {} {}".format(unamid, hex(int.from_bytes(result,'big'))[2:]).encode('utf-8'))

                # insert messages to text box 
                self.textCons.config(state = NORMAL) 
                self.textCons.insert(END, "\n<<" + self.msg + "\n")                     
                self.textCons.config(state = DISABLED) 
                self.textCons.see(END) 

                print(key)
                #client.send(message.encode(FORMAT))	 
            break	

# create a GUI class object 
g = GUI() 
