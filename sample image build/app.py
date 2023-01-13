import sys
import pandas
import numpy
def handler(event, context): 
    return 'Hello from AWS Lambda using Python' + sys.version + '!'