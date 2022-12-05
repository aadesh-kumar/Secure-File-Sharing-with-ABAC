# Secure-File-Sharing-with-ABAC
Secure File sharing between two hosts using client-server architecture with ABAC (Attribute Based Access Control) policies.

# Requirements
Python 3.x
MongoDB
cURL command line tool

Use the following command to install all dependencies
```console
pip install -r requirements.txt
```

# Usage

Write your policies in 'policies.py' file and run it. This will create a database 'py_abac' in your MongoDB.
Then run the 'server.py' file. This will run an HTTP server at port 8000 on your local machine.

In the Clients folder, run the 'up.py' script to upload files to the server. The server then encrypts the files and stores it locally. Use 'down.py' script to download the files to another host.
