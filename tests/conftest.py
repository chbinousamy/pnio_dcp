import os, sys
myPath = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, myPath + '/../tests')

from fixture.instance_dcp import instance_dcp
