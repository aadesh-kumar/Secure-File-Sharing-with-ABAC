#!/usr/bin/env python

import os
from getpass import getpass

username = input('Username: ')
password = getpass()
filename = input('Filename: ')
os.system('curl -X "DELETE" http://localhost:8000/' + username + '/' + password + '/' + filename)