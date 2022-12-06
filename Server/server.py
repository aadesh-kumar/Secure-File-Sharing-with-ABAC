#!/usr/bin/env python
import os
import http.server as server
from pymongo import MongoClient
from py_abac import PDP, Request
from py_abac.storage.mongo import MongoStorage
from cryptography.fernet import Fernet
import socketserver


def evaluatePolicy(subject, resource, action, context):
    # Setup policy storage
    client = MongoClient()
    storage = MongoStorage(client)

    # Create policy decision point
    pdp = PDP(storage)

    # Json Request captures all of access parameters.
    request_json = {
        "subject": {
            "id": "",
            "attributes": { "name": subject}
        },
        "resource": {
            "id": "",
            "attributes": { "name": resource}
        },
        "action": {
            "id": "",
            "attributes": {"method": action}
        },
        "context": context
    }
    # Parse JSON and create access request object
    request = Request.from_json(request_json)

    # Return policy decision whether to allow or deny access.
    return pdp.is_allowed(request)

def listFiles(userName):
    client = MongoClient()
    files = client.py_abac.files.find()
    userFiles = []
    for file in files:
        if evaluatePolicy(userName, file['name'], 'lookup', {'created_by': file['created_by'], 'receiver': file['receiver']}):
            userFiles.append(file['name'])
    return userFiles

def getFile(fileName, userName):
    client = MongoClient()
    file = client.py_abac.files.find_one({"name":fileName})
    if file is None:
        return False
    return evaluatePolicy(userName, fileName, 'get', {'created_by':file['created_by'], 'receiver':file['receiver']})

def createFile(object):
    if evaluatePolicy(object['created_by'], object['name'], 'create', {'created_by': object['created_by']}):
        client = MongoClient()
        client.py_abac.files.insert_one(object)
        return True
    else:
        return False

def deleteFile(fileName, creator):
    client = MongoClient()
    file = client.py_abac.files.find_one({"name":fileName})
    if file is None:
        return False
    if evaluatePolicy(creator, fileName, 'delete', {'created_by': file['created_by']}):
        client.py_abac.files.delete_one({"name": fileName})
        return True
    else:
        return False

def decryptFile(FileName):
    with open('FileKey.key', 'rb') as filekey:
        key = filekey.read()

    fernet = Fernet(key)

    with open('./Files/' + FileName, 'rb') as enc_file:
        encrypted = enc_file.read()

    decrypted = fernet.decrypt(encrypted)
    
    with open('./Files/' + FileName, 'wb') as dec_file:
        dec_file.write(decrypted)

def encryptFile(filename):
    with open('FileKey.key', 'rb') as filekey:
        key = filekey.read()
    
    fernet = Fernet(key)

    with open('./Files/' + filename, 'rb') as file:
        original = file.read()
        
    encrypted = fernet.encrypt(original)
    
    with open('./Files/' + filename, 'wb') as encrypted_file:
        encrypted_file.write(encrypted)

class HTTPRequestHandler(server.SimpleHTTPRequestHandler):
    
    def do_PUT(self):
        filename = os.path.basename(self.path)

        # Checks if file is already uploaded
        if os.path.exists('./Files/' + filename):
            self.send_response(409, 'Conflict')
            self.end_headers()
            reply_body = '"%s" already exists\n' % filename
            self.wfile.write(reply_body.encode('utf-8'))
            return
        params = self.path.split('/')

        # Create Policies are enforced here
        if not createFile({"name": params[3], "created_by": params[1], "receiver": params[2]}):
            self.send_response(404)
            self.end_headers()
            reply_body = 'Policy Error\n'
            self.wfile.write(reply_body.encode('utf-8'))
            return

        file_length = int(self.headers['Content-Length'])
        read = 0
        if not os.path.isdir("Files"):
            os.mkdir('Files')
        with open('./Files/' + filename, 'wb+') as output_file:
            while read < file_length:
                new_read = self.rfile.read(min(66556, file_length - read))
                read += len(new_read)
                output_file.write(new_read)
        
        # File is encrypted for security reasons.
        encryptFile(filename)
        
        self.send_response(201, 'Created')
        self.end_headers()
        reply_body = 'Saved "%s"\n' % filename
        self.wfile.write(reply_body.encode('utf-8'))
    
    def do_DELETE(self):
        try:
            params = self.path.split('/')
            # Delete Policies are enforced here.
            if not deleteFile(params[2], params[1]):
                self.send_response(404)
                self.end_headers()
                reply_body = 'Policy Error\n'
                self.wfile.write(reply_body.encode('utf-8'))   
                return

            os.remove('./Files/' + params[2])
            self.send_response(200)
            self.send_header('Content-type','text/plain')
            self.end_headers()
            message = "Deleted " + params[2]
            self.wfile.write(bytes(message, "utf8"))
        except Exception as e:
            print(e)
    
    def do_GET(self):
        try:
            params = self.path.split('/')
            if len(params) < 3:
                # Lookup request
                files = listFiles(params[1])
                self.send_response(200)
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                for file in files:
                    self.wfile.write(bytes(file, 'utf-8'))
            else:
                # Get request
                # Get Policies are enforced here.
                if not getFile(params[2], params[1]):
                    self.send_response(404)
                    self.end_headers()
                    reply_body = 'Policy Error\n'
                    self.wfile.write(reply_body.encode('utf-8'))
                    return
                self.send_response(200)
                self.send_header('Content-type','application/octet-stream')
                self.send_header('Content-Disposition', 'attachment; filename=%s' % params[2])
                self.end_headers()

                decryptFile(params[2])

                with open('./Files/' + params[2], 'rb') as f:
                    self.wfile.write(f.read())
            
        except Exception as e:
            print(e)

if __name__ == '__main__':
    PORT = 8000
    Handler = HTTPRequestHandler
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("HTTP server running at port", PORT)
        httpd.serve_forever()