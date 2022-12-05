#!/usr/bin/env python

import os
import sys

if len(sys.argv) == 4:
    os.system('curl -X PUT --upload-file ' + str(sys.argv[3]) + ' http://localhost:8000/' + str(sys.argv[1]) + '/' + str(sys.argv[2]) + '/' + str(sys.argv[3]))
else:
    print('Usage:')
    print('download.py Sender Receiver File')