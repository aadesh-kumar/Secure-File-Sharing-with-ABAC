#!/usr/bin/env python3

import os
from getpass import getpass

username = input('Username: ')
password = getpass()
os.system('curl -f http://localhost:8000/list/' + username + '/' + password)