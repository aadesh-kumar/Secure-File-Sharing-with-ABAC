#!/usr/bin/env python3

import os
import sys

if len(sys.argv) == 2:
    os.system('curl -f http://localhost:8000/' + str(sys.argv[1]))
else:
    print('Usage:')
    print('list.py User')