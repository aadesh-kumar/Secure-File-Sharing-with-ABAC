#!/usr/bin/env python

import os
from getpass import getpass

username = input('Username: ')
password = getpass()
receiver = input('Receiver: ')
filename = input('Filename: ')
os.system('curl -X PUT --upload-file ' + filename + ' http://localhost:8000/' + username + '/' + password + '/' + receiver + '/' + filename)