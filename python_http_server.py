from http.server import BaseHTTPRequestHandler, HTTPServer
import http.cookies
import socket
import urllib.parse
import json
import os
import base64
import hashlib
from datetime import datetime
from datetime import timedelta
server_address=("",10001)
rootFolder ="./" #map it to any folder
passwd_file =".passwd"
active_file =".active"

def isLogged(token):
    try:
        with open(active_file,'r') as rfd:
            file_read = rfd.read()
            if(file_read == ''):
                return False
        users = json.loads(file_read)
        if(token not in users.keys()):
            return False
        now = datetime.now()
        expiry_time = datetime.strptime(users[token],'%Y-%m-%d %H:%M')
        return expiry_time > now
    except:
        return False
        
    

def getHandler():
    class MyHandler(BaseHTTPRequestHandler):
        def typeExtractor(self,path):
            contentType = "text/html"
            if(path[-3:-1] == "png"):
                contentType ="image/png"
            elif path[-3:-1] == "css":
                contentType="text/css"
            elif(path[-3:-1] == "ico"):
                contentType="image/vnd"
            elif path[-3:-1] == "tff":
                contentType="font/ttf"
            elif path[-4:-1] == "woff" or path[-5:-1] == "woff2":
                contentType="font/woff"
            return contentType
        def readHTML(self,htmlPath):
            html =""
            response_code =200
            try:
                if(htmlPath == "/"):
                    htmlPath ="/index.html"
                with open(rootFolder+htmlPath,"rb") as fd:
                    html = fd.read()
            except FileNotFoundError:
                response_code =404
            return (html,response_code)
        def do_GET(self):
            response,code = self.readHTML(self.path)
            if(code == 200):
                self.send_response(200)
                self.send_header('content-type',self.typeExtractor(self.path))
                self.end_headers()
                self.wfile.write(response)
            else:
                self.send_error(404)
        def do_POST(self):            
            if(self.path == "/terminal.html"):
                token = self.headers.get('Cookie','token=').split("token=")[1].strip()
                print("The token is:",token)
                if(not isLogged(token)):
                    self.send_response(302)
                    self.send_header('content-type','text/html')
                    self.send_header('location','/login.html')
                    self.end_headers()
                else:
                    content_len = int(self.headers.get("content-length"))
                    post_body = self.rfile.read(content_len).decode()
                    post_body = urllib.parse.unquote(post_body)
                    command = post_body.split("=")[1].replace("+", " ") 
                    response =os.popen(command).read()
                    self.send_response(200)
                    self.send_header('content-type','text/html')
                    self.end_headers()
                    response_list =response.splitlines()
                    p_str = ""
                    for output in response_list:
                        p_str += f'<li class="list-group-item disabled" aria-disabled="true">{output}</li>'
                    response_html =f"""
                    <!DOCTYPE html>
                    <html>
                        <head>
                            <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@4.6.2/dist/css/bootstrap.min.css" integrity="sha384-xOolHFLEh07PJGoPkLv1IbcEPTNtaed2xpHsD9ESMhqIYd0nLMwNLD69Npy4HI+N" crossorigin="anonymous">
                            <title>RUN CMD</title>
                        </head>
                        <body class="container">
                            <h1 class="text-center font-weight-bold text-secondary">WELCOME TO OPEN A TERMINAL IN THE SERVER</h1>
                            <hr/>
                            <form method="post">
                                <div class="form-group">
                                  <label for="exampleFormControlInput1">Enter a command</label>
                                  <input type="text" class="form-control" name="command" id="command" value="{command}">
                                </div>
                              </form>    
                            <div>
                                <ul class="list-group">
                                  {p_str}
                                </ul>

                            </div>    
                        </body>
                    </html>
                    """
                    self.wfile.write(response_html.encode())
            elif(self.path == '/register.html'):
                #create a json hash with username and hashstring 
                content_len = int(self.headers.get("content-length"))
                post_body = self.rfile.read(content_len).decode()
                post_body = urllib.parse.unquote(post_body)
                username = post_body.split("username=")[1].split("password=")[0].strip()[:-1]
                password = post_body.split("username=")[1].split("password=")[1].split("confirm=")[0].strip()[:-1]
                confirm = post_body.split("username=")[1].split("password=")[1].split("confirm=")[1].strip()
                
                username = username.split()[0]
                password = password.split()[0]
                confirm = confirm.split()[0]
                if(password != confirm):
                    self.send_response(302)
                    self.send_header('content-type','text/html')
                    self.send_header('location','/register.html')
                    self.end_headers()
                else:
                    with open(passwd_file,'r') as fd:
                        file_data  = fd.read()
                    if(file_data == ""):
                        accounts = {}
                    else:
                        accounts = json.loads(file_data)
                    if(username in accounts.keys()):
                        self.send_response(302)
                        self.send_header('content-type','text/html')
                        self.send_header('location','/register.html')
                        self.end_headers()
                    else:
                        h = hashlib.sha256()
                        h.update(password.encode())
                        password_hash = base64.b64encode(h.hexdigest().encode())
                        accounts[username] = password_hash.decode()
                        with open(passwd_file,'w') as fd2:
                            fd2.write(json.dumps(accounts))
                            fd2.flush()
                    self.send_response(302)
                    self.send_header('content-type','text/html')
                    self.send_header('location','/login.html')
                    self.end_headers()
                    self.wfile.write("")         
            elif(self.path == '/login.html'):
                #try to map the store hash string with the generated hash.
                content_len = int(self.headers.get("content-length"))
                post_body = self.rfile.read(content_len).decode()
                post_body = urllib.parse.unquote(post_body)
                post_body = post_body.split("username=")[1].split("password=")
                username,password =post_body[0].strip()[:-1],post_body[1].strip()
                
                with open(passwd_file,'rb') as fd:
                    file_output = fd.read()
                    if(file_output == ""):
                        accounts = {}
                    else:
                        accounts = json.loads(file_output)
                    if username in accounts.keys():
                        h = hashlib.sha256()
                        h.update(password.encode())
                        password_hash = base64.b64encode(h.hexdigest().encode())
                        hashed_passwd = password_hash.decode()#generate hash_password
                        if(hashed_passwd == accounts[username]):
                            with open(active_file,"r") as rfd:
                                active_records = rfd.read()
                            if(active_records == ""):
                                active_accounts = {}
                            else:
                                active_accounts = json.loads(active_records)
                            active_accounts[username] = (datetime.now() + timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M")
                            with open(active_file,'w') as wfd:
                                active_json = json.dumps(active_accounts)
                                wfd.write(active_json)
                                wfd.flush() 
                            self.send_response(302)
                            self.send_header('content-type','text/html')
                            cookie = http.cookies.SimpleCookie()
                            cookie['token'] = username
                            self.send_header('Set-Cookie',cookie.output(header='',sep=''))
                            self.send_header('location','/terminal.html')
                            self.end_headers()
                        else:
                            self.send_response(302)
                            self.send_header('content-type','text/html')
                            self.send_header('location','/login.html')
                            self.end_headers()
                    else:
                        self.send_response(302)
                        self.send_header('content-type','text/html')
                        self.send_header('location','/login.html')
                        self.end_headers()
            else:
                self.send_error(404)
    return MyHandler
                
def run(server_class=HTTPServer, handler_class=BaseHTTPRequestHandler):
        httpd = server_class(server_address,handler_class)
        httpd.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        httpd.serve_forever()
        
run(server_class=HTTPServer,handler_class=getHandler())    
