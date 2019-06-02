#!env python3.7

import requests
import re
import logging
import calendar
import datetime
import time
import random

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
        # получение mos_id
        r_handler = self._ps.get("https://stats.mos.ru/handler/handler.js")
        # получение session-cookie
        r_enter = self._ps.get(popular)
        # получение ACS-SESSID
        r_opts = self._ps.get("https://www.mos.ru/api/oauth20/v1/frontend/json/ru/options")

        r = self._ps.get("https://www.mos.ru/api/acs/v1/login?redirect=https%3A%2F%2Fwww.mos.ru%2Fservices%2Fcatalog%2Fpopular%2F", allow_redirects=False)
        if r.status_code != 303:
            logging.error("Церемония поменялась")
            raise

        # "https://login.mos.ru/sps/oauth/ae?client_id=xxx..&response_type=code
        # &redirect_uri=https://my.mos.ru/my/website_redirect_uri&scope=openid+profile", allow_redirects=False)
        r_ae = self._ps.get(r.headers['location'], allow_redirects=False)
        if r_ae.status_code != 303 or r_ae.headers['Location']!="/sps/login/methods/password":
            logging.error("Церемония поменялась")
            raise
        #ps.cookies.update(r.cookies)
        pdb.set_trace()
        password_cookies={
                'fm': r_ae.cookies['fm'],
                'mos_id' : r_handler.cookies['mos_id'],
                'lstate' : r_ae.cookies['lstate'],
                'oauth_az':r_ae.cookies['oauth_az'],
                'origin': r_ae.cookies['origin']}

        r_password=self._ps.get("https://login.mos.ru"+r_ae.headers['Location'],
                allow_redirects=False, cookies=password_cookies)
        logging.debug("Начало аутентификационной сессии")
        r_opts=self._ps.get("https://www.mos.ru/api/oauth20/v1/frontend/json/ru/options", headers={"referer":popular})
        logging.debug("Вход")
        r_enter=self._ps.get(f"https://www.mos.ru/api/oauth20/v1/frontend/json/ru/process/enter?redirect={popular}",
                cookies=r_opts.cookies, allow_redirects=False)

        if r_enter.status_code !=302:
            logging.error("Церемония поменялась")
            raise
        r_authorize=self._ps.get(r_enter.headers['Location'], allow_redirects=False)
        logging.debug("Переход на форму авторизации")
        if r_enter.status_code !=302:
            logging.error("Церемония поменялась")
            raise
        r_ae2=self._ps.get(r_authorize.headers['Location'], allow_redirects=False)

        if r_ae2.status_code !=303 or r_ae2.headers['Location']!="/sps/login/methods/password":
            logging.error("Церемония поменялась")
            raise

        r_password2=self._ps.get("https://login.mos.ru"+r_ae2.headers['Location'], allow_redirects=False, cookies=r_ae2.cookies)
        if r_password2.status_code != 200 :
            logging.error("Церемония поменялась")
            raise

        logging.debug("Выбираем вариант входа: через госуслуги")

        r_execute=self._ps.get("https://login.mos.ru/sps/login/externalIdps/execute?typ=esia&name=esia_1&isPopup=false",
                headers={"referer": "https://login.mos.ru/sps/login/methods/password"}, 
                cookies=r_ae2.cookies, allow_redirects=False)

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
        r=self._ps.get(r_callback.headers['Location'])
        pdb.set_trace()

        self.Ltpatoken2 = r_callback.cookies['Ltpatoken2']
        milisecs=calendar.timegm(time.gmtime())*1000+random.randint(0,999)+1
        self._ps.cookies["mos_id"]="CllGxlmW7RAJKzw/DJfJAgA="
        pdb.set_trace()
#        r=self._ps.get("https://my.mos.ru/static/xdm/index.html?nocache="+
#                str(milisecs)+"&xdm_e=https%3A%2F%2Fwww.mos.ru&xdm_c=default1&xdm_p=1")
#        self._ps.cookies.update(r.cookies)
#        r=self._ps.get(r.headers['Location'])
#        self._ps.cookies.update(r.cookies) 
#        r=self._ps.get(r.headers['Location']) 
#        self._ps.cookies.update(r.cookies)
#        r=self._ps.get(r.headers['Location'])
#        self._ps.cookies.update(r.cookies)
 
        r_opts = self._ps.get("https://www.mos.ru/api/oauth20/v1/frontend/json/ru/options")

        pdb.set_trace()


        post_token = {
                "system_id": "mos.ru",
                "nonce" : "",
                "timestamp" : "",
                "signature" : ""}

        r_tok=self._ps.post("https://my.mos.ru/data/token", 
                headers={"referer":"https://my.mos.ru/static/xdm/index.html"},
                cookies={"Ltpatoken2":self.Ltpatoken2},
                data=post_token)


        self.Authenticated = self.Ltpatoken2 != ""
        return self.Authenticated

    def GetName(self):
        if not self.Authenticated :
            logging.error("Не аутентифицировано")
            raise

        r_my = self._ps.get("https://my.mos.ru/data/")
