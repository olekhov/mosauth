#!env python3.7

import requests
import re
import logging
import calendar
import datetime
import time
import random
import json

import pdb

from .pguoauth.pguoauth import PGUAuthenticator

class MOSAuthenticator:
    """ Аутентификация на сайте https://pgu.mos.ru """
    def __init__(self,cfg):
        self._cfg = cfg
        self._ps=requests.Session()
        self.Authenticated = False
        pass

    def AuthenticateByESIA(self, esia_cfg):
        popular="https://www.mos.ru/services/catalog/popular/"
        
        logging.debug("Открываем портал www.mos.ru")
        # получение session-cookie
        r_root = self._ps.get("https://www.mos.ru/")
        # получение ACS-SESSID
        r_opts = self._ps.get("https://www.mos.ru/api/oauth20/v1/frontend/json/ru/options")
        # получение mos_id
        #_enter = self._ps.get(popular)

        r_login = self._ps.get("https://www.mos.ru/api/acs/v1/login?redirect=https%3A%2F%2Fwww.mos.ru%2F", allow_redirects=False)
        if r_login.status_code != 303:
            logging.error("Церемония поменялась")
            raise

        # "https://login.mos.ru/sps/oauth/ae?client_id=xxx..&response_type=code
        # &redirect_uri=https://my.mos.ru/my/website_redirect_uri&scope=openid+profile", allow_redirects=False)
        r_ae = self._ps.get(r_login.headers['location'], allow_redirects=False)
        if r_ae.status_code != 303 or r_ae.headers['Location']!="/sps/login/methods/password":
            logging.error("Церемония поменялась")
            raise
        #ps.cookies.update(r.cookies)
        password_cookies={
                'fm': r_ae.cookies['fm'],
                'lstate' : r_ae.cookies['lstate'],
                'oauth_az':r_ae.cookies['oauth_az'],
                'origin': r_ae.cookies['origin']}

        r_password=self._ps.get("https://login.mos.ru"+r_ae.headers['Location'],
                allow_redirects=False, cookies=password_cookies)
        logging.debug("Начало аутентификационной сессии")

        r_execute=self._ps.get("https://login.mos.ru/sps/login/externalIdps/execute?typ=esia&name=esia_1&isPopup=false",
                headers={"referer": "https://login.mos.ru/sps/login/methods/password"}, 
                allow_redirects=False)

        if r_execute.status_code !=303 :
            logging.error("Церемония поменялась")
            raise

        esia_request=r_execute.headers["Location"]
        au = PGUAuthenticator(esia_cfg)
        code=au.AuthenticateByEmail(esia_request, "https://login.mos.ru")

        # в code должен быть хороший ответ типа 
        # https://login.mos.ru/sps/login/externalIdps/callback/esia/esia_1/false?c
        # ode=eyJ2ZXIiOjEsInR5cCI6IkpXVCIsInNidCI6ImF1dGhvcml6YXRpb25fY29...

        callback_cookies={
                'fm': r_ae.cookies['fm'],
                'history': r_execute.cookies['history'],
                'lstate' : r_execute.cookies['lstate'],
                'oauth_az':r_ae.cookies['oauth_az'],
                'origin': r_ae.cookies['origin']}

        #print(code)
        r_callback = self._ps.get(code, allow_redirects=False, 
                cookies=callback_cookies,
                headers={'referer':'https://esia.gosuslugi.ru/'})
        if r_callback.cookies['Ltpatoken2'] != '' :
            logging.debug("Авторизовано успешно")
        self._ps.cookies.update(r_callback.cookies)
        # login/satisfy?code=...
        r=self._ps.get(r_callback.headers['Location'], allow_redirects=False)
        r=self._ps.get("https://www.mos.ru/")
        r_opts = self._ps.get("https://www.mos.ru/api/oauth20/v1/frontend/json/ru/options")

        self.Ltpatoken2 = r_callback.cookies['Ltpatoken2']
        milisecs=calendar.timegm(time.gmtime())*1000+random.randint(0,999)+1
        # obtain NGINXSESSID
        my_req=f"https://my.mos.ru/static/xdm/index.html?nocache={milisecs}&xdm_e=https%3A%2F%2Fwww.mos.ru&xdm_c=default1&xdm_p=1"
        #pdb.set_trace()
        r_my = self._ps.get(my_req,allow_redirects=False)
        # redir to oauth20.mos.ru
        r_auth = self._ps.get(r_my.headers['Location'], allow_redirects=False)
        # redir to login.mos.ru
        r_ae = self._ps.get(r_auth.headers['Location'], allow_redirects=False)
        # redir to my.mos.ru/website_redirect
        r_webredir = self._ps.get(r_ae.headers['Location'], allow_redirects=False)
        # redir to my.mos.ru/../xdm/index.html
        r_index = self._ps.get(r_webredir.headers['Location'], allow_redirects=False)

        opts = json.loads(r_opts.text)
        #pdb.set_trace()
        post_token = {
                "system_id": "mos.ru",
                "nonce" : opts["elk"]["nonce"],
                "timestamp" : opts["elk"]["timestamp"],
                "signature" : opts["elk"]["signature"]}

        r_tok=self._ps.post("https://my.mos.ru/data/token", 
                headers={"referer":my_req},
                data=post_token)
        self.token = json.loads(r_tok.text)['token']

        self.Authenticated = self.token != ""
        return self.Authenticated

    def GetStatus(self):
        if not self.Authenticated :
            logging.error("Не аутентифицировано")
            raise

        r_my = self._ps.get(f"https://my.mos.ru/data/{self.token}/status?site_id=mos.ru")

        return json.loads(r_my.text)

