
from const import URLS,AVAILABLE_COMMANDS,COMMAND_HEADERS,AUTH_HEADERS,AWSCLIENTID
from requests.exceptions import *
from time import time
from os import path

import requests as r
import logging
import json
# import os

# from exceptions import 

log = logging.getLogger(__name__)


class DroneMobile():
    user = None
    secret = None
    IdToken = None
    IdToken_expires = None
    RefreshToken = None
    deviceKey = None
    vin = None
    tokenJson = None
    vehicle_name = None
    
    def user_password_auth(self,user,secret):
        payload = '{'
        payload += '"AuthFlow":"USER_PASSWORD_AUTH",'
        payload += f'"ClientId":"{AWSCLIENTID}",'
        payload += '"AuthParameters":{'
        payload += f'"USERNAME":"{user}",'
        payload += f'"PASSWORD":"{secret}"'
        payload += '},'
        payload += '"ClientMetadata":{}'
        payload += '}'
        return payload


    def refresh_token_auth(self,refresh_token):
        payload = '{'
        payload += f'"ClientId":"{AWSCLIENTID}",'
        payload += '"AuthFlow":"REFRESH_TOKEN_AUTH",'
        payload += '"AuthParameters":{'
        payload += f'"REFRESH_TOKEN":"{refresh_token}"'
        payload += '}'
        payload += '}'
        return payload

    def command_body(self,deviceKey,command):
        payload = '{'
        payload += f'"deviceKey":"{deviceKey}",'
        payload += f'"command":"{command}"'
        payload += '}'
        return payload

    def __init__(self,tokenJson,user=None,secret=None,deviceKey=None,vin=None,
                    vehicle_name=None):
        # user will id car by VIN or DroneMobile 'deviceKey' to avoid naming conflict if
        # multiple on account
        self.user = user
        self.secret = secret
        if vin:
            log.info('Using VIN for ID...')
        elif deviceKey:
            log.info('Using "deviceKey" for ID...')
        elif vehicle_name:
            log.info('Using vehicle_name for ID...')
        else:
            log.info('no vehicle info provided')
        
        self.vin = vin
        self.deviceKey = deviceKey
        self.vehicle_name = vehicle_name
        self.vehicleInfo = None
        self.tokenJson = tokenJson
        
        self.getToken()
        self.authenticate()
        self.vehicleInfoGet()

    def authenticate(self):
        #get IdToken via user/secret authentication
        if self.user and self.secret:
            _body = self.user_password_auth(self.user,self.secret)
            log.info('Using user/pass')
            _method = 'User/Password Combo'
        #get IdToken using refresh token, time out appears to be about 3 months 
        elif self.RefreshToken is not None:
            if self.IdToken_expires > time():
                log.info('IdToken is still valid')
                _method = 'IdToken'
                log.info(f'Authenticated using {_method}')
                return True
            else:
                log.info('IdToken Expired...')
                _body = self.refresh_token_auth(self.RefreshToken)
                log.info('Using refresh_token')
                _method = 'Refresh Token'
        else:
            raise Exception("Must provide a valid user/password combination.")

        _headers = AUTH_HEADERS
        
        try:
            _response = r.post(URLS['auth'], headers=_headers, data=_body) 
            _response.raise_for_status()
        except HTTPError as h:
            message = _response.json()['message']
            raise Exception (f'{h} {message}')
        except Exception as e:  
            log.error(e ,exc_info=True)
            log.error(_response.text)
            return False
        else:
            _auth = _response.json()['AuthenticationResult']
            self.IdToken = _auth['IdToken']
            if 'RefreshToken' in _auth:
                self.RefreshToken = _auth['RefreshToken']
            self.IdToken_expires = (time() - 100) + _auth['ExpiresIn']
            log.info(f'Authenticated using {_method}')
            self.saveToken()
            return True
            
    def saveToken(self):
        tokens = {
            'RefreshToken':self.RefreshToken,
            'IdToken':self.IdToken,
            'IdToken_expires':self.IdToken_expires
            
        }
        with open(self.tokenJson, 'w+') as tj:
            
            json.dump(tokens,tj,indent=4,sort_keys=True)
            log.info('saved tokens.')
        
        
    def getToken(self):
        if self.tokenJson is not None:
            if path.exists(self.tokenJson):
                with open(self.tokenJson,'r') as tj:
                    tokens = json.load(tj)
                    self.IdToken = tokens['IdToken']
                    self.IdToken_expires = tokens['IdToken_expires']
                    self.RefreshToken = tokens['RefreshToken']
                    log.info('loaded tokens')
                    return True
        else:
            return False


    class Decorators():
        @staticmethod
        def refreshToken(decorated):
            def wrapper(api, *args, **kwargs):
                if api.RefreshToken is None:
                    log.info('RefreshToken not found')
                    api.authenticate()
                elif time() > api.IdToken_expires:
                    log.info('IdToken expired, refreshing...')
                    api.authenticate()
                return decorated(api, *args, **kwargs)

            return wrapper

    @Decorators.refreshToken
    def vehicleInfoGet(self): # search for given vehicle 
        _url = URLS['vehicle_info']
        _bearer = 'Bearer ' + self.IdToken
        _headers = {'Authorization': _bearer}
        try:
            _response = r.get(_url, headers=_headers)
            _response.raise_for_status()
        except Exception as e:

            return f'{e}  {_response}'
        else:
            _results = _response.json()['results']
            for _result in _results:
                if self.vin:
                    _test_vin = _result.get('vin')
                    if _test_vin == self.vin:
                        log.info('found VIN in results')
                        self.vehicleInfo = _result
                elif self.deviceKey:
                    _test_key = _result.get('device_key')
                    if _test_key == self.deviceKey:
                        log.info('found deviceKey in results')
                        self.vehicleInfo = _result
                elif self.vehicle_name:
                    _test_key = _result.vehicle_name
                    log.info('found vehicle_name in results')
                    self.vehicleInfo = _result
                else: 
                    self.vehicles = _results
    
    def vehicleInfoCallback(self,data): # Update vehicle attributes after a command is sent
        for key in data['parsed']:
            if key in self.vehicleInfo:
                val = data['parsed'][key]
                if not self.vehicleInfo[key] == val:
                    self.vehicleInfo[key] = val
                    log.info(f'{key} updated: {val}')

    
    @Decorators.refreshToken
    def sendCommand(self, command):
        if not command in AVAILABLE_COMMANDS:
            raise Exception  #InvalidCommandException
        else:
            log.info(f'sending command: {command}')
        _url = URLS['command']
        _headers = COMMAND_HEADERS
        _headers['x-drone-api'] = self.IdToken
        _body = self.command_body(self.deviceKey,command)
        try:
            _response = r.post(_url, headers=_headers, data=_body)
           
            _response.raise_for_status()
        except Exception as e:
            log.info(e ,exc_info=True)
            log.info(_response.text)
            return _response
        else:
            log.info('Command Successful!')
            self.vehicleInfoCallback(_response.json())
            return _response