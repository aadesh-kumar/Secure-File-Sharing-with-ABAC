#!/usr/bin/env python

import os
import sys

if len(sys.argv) == 3:
    os.system('curl -X "DELETE" http://localhost:8000/' + str(sys.argv[1]) + '/' + str(sys.argv[2]))
else:
    print('Usage:')
    print('delete.py User File')