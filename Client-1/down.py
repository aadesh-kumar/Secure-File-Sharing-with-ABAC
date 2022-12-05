#!/usr/bin/env python3

import os
import sys

if len(sys.argv) == 3:
    os.system('curl -f --create-dirs http://localhost:8000/' + str(sys.argv[1]) + '/' + str(sys.argv[2]) + ' -o Downloads/' + str(sys.argv[2]))
else:
    print('Usage:')
    print('download.py User File')