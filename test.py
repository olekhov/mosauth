#!env python3.7

import json
import logging
from mosauth import MOSAuthenticator

logging.basicConfig(level=logging.DEBUG) 
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("chardet").setLevel(logging.WARNING)
                                                                         
with open('config.json') as json_data_file:                         
    pguconfig = json.load(json_data_file)     

mosau = MOSAuthenticator({})

mosau.AuthenticateByESIA(pguconfig)

