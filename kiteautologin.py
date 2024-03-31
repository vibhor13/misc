#!/usr/bin/env python3
import json
import requests
import pyotp
from kiteconnect import KiteConnect
from kiteconnect import KiteTicker
import configparser
import os
# import pandas as pd 

def zerodha_autologin():

    login_url = "https://kite.zerodha.com/api/login"
    twofa_url = "https://kite.zerodha.com/api/twofa"
    request_token = ''

    ## GET CURRENT USER
    username=os.getlogin()
    
    #Create session and login   
    ## READ CONFIG FROM CONFIG FILE
    config = configparser.RawConfigParser()
    home_dir = os.path.expanduser('~')
    config_loc = os.path.join(home_dir, '.creds.txt')
    try:
        config.read(config_loc)
    except Exception as e:
        print("Couldn't open the config file at : ~/.creds.txt")

    config_dict = dict(config.items('AUTH'))
 
    session = requests.Session()
    response = session.post(login_url, data={'user_id':config_dict['kite_user'], 
                                             'password': config_dict['kite_password']})
    request_id = json.loads(response.text)['data']['request_id']
    twofa_pin = pyotp.TOTP(config_dict['totp_key']).now()
    response = session.post(twofa_url, data={'user_id':config_dict['kite_user'],
                                              'request_id':request_id,
                                              'twofa_value': twofa_pin,
                                              'twofa_type':'totp'})
    kite = KiteConnect(api_key=config_dict['api_key'])
    try:
        response=session.get(kite.login_url(),allow_redirects=True).url

    except Exception as e :
        e = str(e)
        request_token = e.split('request_token=')[1].split(' ')[0].split('&action')[0]
    
    print('Login to kite successful with request token')
    access_token = kite.generate_session(request_token, config_dict['api_secret'])['access_token']
    print('Successfully obtained access_token')
    kite.set_access_token(access_token)
    print('Login successful .')
    kws = KiteTicker(config_dict['api_key'],access_token)

    # print(pd.DataFrame(kite.holdings()))

    return(kite, kws)




if __name__  ==  "__main__" :  # Prevents running the login function if not called directly . 
    zerodha_autologin()  

    