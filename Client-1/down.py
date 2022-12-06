#!/usr/bin/env python3

import os
from getpass import getpass

username = input('Username: ')
password = getpass()
file = input('Filename: ')
os.system('curl -f --create-dirs http://localhost:8000/download/' + username + '/' + password + '/' + file + ' -o Downloads/' + file)