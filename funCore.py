# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     main
   Description :  
   Author :       Administrator
   date：          2018-10-08
-------------------------------------------------
   Change Activity:
                   2018-10-08:
-------------------------------------------------
"""
__author__ = 'Sto'
import websocket
import requests
import json
import random
import time
import re
import logging # 日志模块
from utils.util import CodeUtils,TextUtils,Time_utils,Date_utils
from utils.log import Logs
from retrying import retry

# 是否启用webSocket跟踪？
websocket.enableTrace(False)
# 不提示 https证书警告
requests.packages.urllib3.disable_warnings()

# 日志模块设置
logging.basicConfig(filename='logs.log',
                    format='%(asctime)s-%(levelname)s-%(module)s:%(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S %p',
                    level=logging.INFO)

# 记录领取的
myLog = Logs("./领取记录.txt")

# 回调事件
dic_cls_relation = {} # 类关系


def on_message(ws, message):
    """
    收到消息事件
    :param ws: 
    :param message: 
    :return: 
    """
    cls = dic_cls_relation.get(ws)
    if cls:
        cls.on_message(message);



def on_error(ws, error):
    """
    wss 错误事件
    :param ws: 
    :param error: 
    :return: 
    """
    logging.error("wss错误回调："+str(error))


def on_close(ws):
    """
    关闭事件
    :param ws: 
    :return: 
    """
    cls = dic_cls_relation.get(ws)
    if cls:
        cls.on_close();
        del dic_cls_relation[ws]


def on_open(ws):
    """
    连接已打开事件，已经连接成功
    :param ws: 
    :return: 
    """
    cls = dic_cls_relation.get(ws)
    if cls:
        cls.on_connect_success()





class Reptilian(object):
    """
    爬虫类
    """
    def __init__(self,Website,user,pwd):
        """
        初始化
        :param Website:  网址
        :param user:  登录账号
        :param pwd:  登录密码
        """
        self.Website_yuan = Website
        self.remarks = TextUtils.getTextMiddle(Website,"[","]")
        if TextUtils.isEmpty(self.remarks):
            self.remarks = TextUtils.getTextMiddle(Website,".",".")
        if TextUtils.isEmpty(self.remarks):
            self.remarks = Website

        findX = Website.find("[")
        if findX != -1:
            Website = Website[:findX]
        self.Website = Website
        self.user = user
        self.pwd = pwd
        self.session = requests.session()
        # 设置默认浏览器UA
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0"
        }
        self.msg = "暂无状态！" # 目前状态标记
        self.chatUrl = None # 连接地址，红包地址
        self.token = None # 登录聊天室用的token和领取红包用的
        self.ws = None # ws连接对象
        self.is_user_normal = True # 账号是否正常
        self.is_login = False # 未登录
        self.is_login_work = False # 账号是否在登录工作
        self.debug = False # 是否调试

    def logs_e(self,errMsg,is_show = False):
        """
        错误信息
        :param errMsg: 
        :return: 
        """
        logging.error("[%s,%s]"%(self.Website_yuan,self.user) +errMsg)
        if self.debug or is_show:
            print("[%s,%s]" % (self.Website_yuan, self.user) + errMsg)

    def logs_i(self, errMsg,is_show = False):
        """
        错误信息
        :param errMsg: 
        :return: 
        """
        logging.info("[%s,%s]" % (self.Website_yuan, self.user) + errMsg)
        if self.debug or is_show:
            print("[%s,%s]" % (self.Website_yuan, self.user) + errMsg)


    def logs(self,errMsg,is_show = False):
        myLog.y("[%s,%s]" % (self.Website_yuan, self.user) + errMsg)
        if self.debug or is_show:
            print("[%s,%s]" % (self.Website_yuan, self.user) + errMsg)

    def logs_d(self, errMsg,is_show = False):
        if self.debug:
            print("[%s,%s]" % (self.Website_yuan, self.user) + errMsg)



    @retry(stop_max_attempt_number=3)
    def requests_get(self, url, params=None, **kwargs):
        """
        发送get请求
        :param url: 
        :param params: 
        :param kwargs: 
        :return: 
        """
        # kwargs["allow_redirects"] = False  # 禁止302
        return self.session.get(url, params=params, **kwargs)


    @retry(stop_max_attempt_number=3)
    def requests_post(self, url, data=None, json=None, **kwargs):
        """
        发送post请求
        :param url: 
        :param data: 
        :param json: 
        :param kwargs: 
        :return: 
        """
        # kwargs["allow_redirects"] = False  # 禁止302
        # kwargs["cookies"] = self.cookies
        return self.session.post(url, data=data, json=json, **kwargs)



    def login(self):
        """
        登录账号
        :return: 成功返回Ture 
        """
        if not self.is_user_normal:
            raise Exception("[密码]异常账号，禁止登录。")

        if self.user_heartbeat():
            self.is_login = True  # 已登录
            return True

        self.msg = "正在登录账号！"
        self.logs_d(self.msg)
        self.close_wss() # 不管有没有连接wss 断开

        url = self.Website + "/api/login.do"
        post = "account=%s&password=%s&pwdtext=%s&loginSrc=0"%(self.user,CodeUtils.md5(self.pwd),self.pwd)
        # 设置协议头
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": self.Website + "/home/"
        }
        r = self.session.post(url,data=post,headers=headers,verify=False)
        # {"success":false,"msg":"密码不正确","info":"","code":400}
        # {"token":"g/g4NZgFg2dHFBjL48fWdsDhSicCSFpR/K6X7O/QJ1LC9m8ldbh9dA==","serverTime":"2018-10-08 09:00:12","userId":2654252,"userName":"yeskpd","fullName":"阿士大夫撒大","loginTime":"2018-10-08 09:00:12","lastLoginTime":"2018-10-08 00:00:12","money":0.0,"email":"+G9PlqmV2UQzpqRUC4Dc+w==","rechLevel":"0","hasFundPwd":true,"testFlag":0,"updatePw":0,"updatePayPw":0,"state":1}

        _json = json.loads(r.text)
        # 获取登录成功后的token
        token = _json.get("token")
        if token:
           # self.cookies = "x-session-token=" + r.cookies.get("x-session-token")
           self.is_login = True # 已登录
           self.msg = "账号登录成功！"
           self.logs_d(self.msg)
           self.logs_i(self.msg, True)
           return True
        # 失败
        self.msg = _json.get("msg","未知登录错误！")
        if self.msg.find("密码") != -1:
           self.is_user_normal = False # 标记账号异常，不要继续登录了
        self.logs_e("登录失败："+self.msg,True)
        self.logs_d(self.msg)
        raise  Exception(self.msg)


    def loadConfigjs(self):
        """
        加载网站配置
        :return: 
        """
        if self.chatUrl:
            return  True
        self.msg = "加载网站配置！"
        self.logs_d(self.msg)
        url = self.Website + "/static/data/configjs.js?v=3062&version=2.26"
        r = requests.get(url,verify=False)
        text = r.text
        findX = text.find("{")
        if findX == -1:
            return False
        _json = json.loads(text[findX - 1:])
        self.chatUrl = _json.get("chatUrl")
        if self.chatUrl:
            self.msg = "网站配置加载成功！"
            self.logs_d(self.msg)
            return True
        self.msg = "网站配置加载失败！"
        self.logs_d(self.msg)
        return False


    def getToken(self):
        """
        获取Token
        :return: 成功返回Token
        """
        self.msg = "获取Sign账号签名"
        self.logs_d(self.msg)

        url = self.Website + "/api/getSign.do?_t="+Time_utils.getNowTimeNum();
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
            "Referer": self.Website + "/game/"
        }
        r = self.session.get(url,headers=headers,verify=False)
        # {"platCode":"sxv1","betMoney":0.0,"signTime":"2018-10-08 09:12:17","sign":"892ff39fc7bab6476ac551c4629e59f5","rechMoney":0.0,"userType":1,"userName":"yeskpd","userId":2654252}
        _json = json.loads(r.text)
        if not _json.get("sign"):
            self.msg = "获取Sign账号签名失败！"
            self.logs_d(self.msg)
            self.logs_e("账号签名获取失败："+r.text)
            return False

        # 获取登录成功后的token
        self.msg = "正在获取账号Token。"
        self.logs_d(self.msg)

        data = None;
        for k, v in _json.items():
            if data:
                data += "&" + k + "=" + CodeUtils.url_encode(str(v))
            else:
                data = k + "=" + CodeUtils.url_encode(str(v))

        # 得到token
        url = self.chatUrl + "/chat/init.do?_t=1538961171663"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0",
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "Referer": self.Website + "/game/",
            "Origin": self.Website
        }
        r = self.session.post(url,data=data,headers=headers,verify=False)
        _json = json.loads(r.text)
        token = _json.get("token")
        if token == None:
            self.msg = "获取账号Token失败！"
            self.logs_d(self.msg)
            self.logs_e("获取账号Token失败：" + r.text)
            raise Exception("token获取失败")
        self.token = token
        self.msg = "账号Token获取成功："+token
        self.logs_d(self.msg)

        return token


    def is_accord_heartbeat(self):
        """
        是否符合心跳
        :return: 
        """
        if self.is_login_work: # 正在执行登录工作，无法继续登录
            return False
        if self.is_user_normal == False: # 账号异常，无需检查心跳
            return False
        # 无其他异常，检查账号状态
        return True


    def user_heartbeat(self):
        """
        账号心跳
        :return: 掉线返回False
        """
        if not self.is_login:
            return False
        try:
            self.logs_d("发送账号心跳.")
            url = self.Website + "/game/getUserMsg.do?_t="+Time_utils.getNowTimeNum()
            headers = {
                "Accept": "application/json, text/plain, */*",
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/69.0.3497.81 Safari/537.36",
                "Referer": "https://www.dt00.com/game/"
            }
            r = self.session.get(url,headers=headers,verify=False)
            if r.text.find("登录无效") != -1:
                self.is_login = False
                self.close_wss()
                self.logs_e("登录信息已过期。")
                return False
            self.logs_d("账号会话正常。")
            return True
        except Exception as e:
            # 心跳一次，无需处理，可能是网络网通 视为账号会话正常
            return True

    def is_connect(self):
        """
        是否已连接wss服务器
        :return: 
        """
        return self.ws != None



    def on_envelopes(self,jsonStr):
        """
        红包通知
        13:50|[888.00|688个]条件:5000充值|5000流水
        :param jsonStr: {"id":17881,"totalMoney":888.0,"totalNum":688,"surplusNum":688,"surplusMoney":888.0,"rechMoney":5000.0,"betMoney":5000.0,"status":"1"}
        :return:  
        """
        str_msg = None
        try:
            _json = json.loads(jsonStr)
            _id = _json.get("id",0);
            if _id < 1 or _json.get("status","0") != "1":
                return
            # 信息开头
            str_msg = "%s|%s|%s|[%s|%s]条件:%s充值-流水:%s|"%(
                Date_utils.getNowDateStr("%H:%M:%S"),
                self.remarks,
                _id,
                _json.get("totalMoney"),
                _json.get("totalNum"),
                _json.get("rechMoney"),
                _json.get("betMoney")
                )

            self.logs_d(self.msg)
            self.logs("红包：{%s}"%str_msg)

            url = self.chatUrl + "/chat/luckyBag.do?_t="+Time_utils.getNowTimeNum()
            data = "token=" +self.token+ "&packetId=" + str(_id)

            self.logs_i ("抢包数据体：[url:%s,data:%s]"%(url,data))

            headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0",
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": "zh-cn,zh;q=0.8,en-us;q=0.5,en;q=0.3",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Referer": self.Website+"/game/",
                "Origin": self.Website
            }
            self.logs_i(str_msg + "提交抢包...")
            r = self.requests_post(url,data=data,headers=headers,verify=False)

            self.logs_i(str_msg + "结果[：%s"% r.text)
            _json = json.loads(r.text)
            resultCode = _json.get("result",-1)
            if resultCode == 0:
                # 抢包成功
                str_msg  += "成功抢到[%s]元"%str(_json.get("money"))
            elif resultCode == 1:
                # 条件不达标
                str_msg += "条件不达标！"
            elif resultCode == 2:
                # 条件不达标
                str_msg += "已抢完!"
            elif resultCode == 3:
                str_msg += "曾经领取过"
            else:
                # 错误，未知！
                str_msg += _json.get("msg","未知领取错误！"+r.text)

            self.msg = str_msg
            self.logs_i(self.msg )
            self.logs( self.msg )
            print(self.msg)

        except Exception as e2:
            if str_msg:
                # 有记录
                self.msg = str_msg+str(e2)
                self.logs_e(  self.msg )
                self.logs(self.msg)
            else:
                # 无记录
                self.msg = "抢包异常错误：" +  str(e2)
                self.logs_e( self.msg)
            print(self.msg)




    def connect_wss(self):
        """
        连接wss
        :return: 成功，进入等待 失败 返回False
        """
        try:
            # 加载token
            if not self.getToken():
                raise Exception("token获取失败！")

            header = {"Connection": "Upgrade",
                      "Pragma": "no-cache",
                      "Cache-Control": "no-cache",
                      "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:35.0) Gecko/20100101 Firefox/35.0",
                      "Upgrade": "websocket",
                      "Origin": self.chatUrl,
                      "Sec-WebSocket-Version": "13",
                      # "Accept-Encoding": "gzip, deflate, br",
                      "Accept-Language": "zh-CN,zh;q=0.9"
                      }
            # 处理wss地址
            wssUrl = "wss://" + self.chatUrl.replace("https://","").replace("http://","")
            wssUrl += "/webchat/"+str(random.randint(100,999))+"/kx1orcey/websocket"

            # 创建webSocket应用
            self.ws = websocket.WebSocketApp(wssUrl,
                                             on_message=on_message,
                                             on_error=on_error,
                                             on_close=on_close,
                                             on_open=on_open,
                                             header=header
                                             )
            # 加到关字典中，方便回调
            dic_cls_relation[self.ws] = self
            # 启动/运行
            self.ws.run_forever()
            # 如果执行到这里表示断开了
            self.ws = None
        except Exception as e:
            self.ws = None
            self.logs_e("连接wss失败："+str(e))



    def close_wss(self):
        try:
            if self.ws:
                self.ws.close()
                self.logs_i("wss主动调用关闭...")
        except Exception as e:
            self.logs_e("关闭连接异常："+str(e))


    def sendWs(self,data):
        """
        发送ws数据
        :param data: 
        :return: 
        """
        self.ws.send(data)


    def on_connect_success(self):
        """
        连接成功通知 
        :return:  没报错说明成功
        """
        self.msg = "正在登录聊天室！"

        time.sleep(0.5)
        # 验证token信息？
        str1 = r'["CONNECT\ntoken:'+self.token+r'\nroomId:1\naccept-version:1.1,1.0\nheart-beat:10000,10000\n\n\u0000"]'
        self.sendWs(str1)

        time.sleep(0.5)
        # 获取历史消息？
        str1 = r'["SUBSCRIBE\ntoken:'+self.token+r'\nroomId:1\nid:sub-0\ndestination:/app/init\n\n\u0000"]'
        self.sendWs(str1)

        time.sleep(0.5)
        # 应该是告诉服务器 我要接受消息
        str1 = r'["SUBSCRIBE\nid:sub-1\ndestination:/server/message/1\n\n\u0000"]'
        self.sendWs(str1)

        time.sleep(0.5)
        # 未知
        str1 = r'["SUBSCRIBE\nid:sub-2\ndestination:/user/'+self.token+r'/queue\n\n\u0000"]'
        self.sendWs(str1)

        self.msg = "连接已建立！"
        self.logs_i("已成功建立wss...",True)


    def on_message(self,data):
        """
        消息进入通知
        :param ws: 
        :return: 
        """
        find_x = data.find(r"\n\n")
        if find_x ==-1:
            return
        data = TextUtils.getTextMiddle(data,r"\n\n",r'\u0000"]').replace(r'\"',r'"');
        res = re.findall(r',"content":"({.*?})",',data)
        for _ in res:
            self.on_envelopes(_.replace(r'\\"',r'"'))



    def on_close(self):
        """
        连接被关闭
        :return: 
        """
        try:
            self.ws = None
            self.logs_i("wss连接被关闭....",True)
            self.msg = "连接已关闭！"
            del dic_cls_relation[self.ws]
        except Exception as e:
            pass





if __name__ == '__main__':
    # r = Reptilian("https://www.jx1108.com[jx1108]","yeskpd","a123456")
    r = Reptilian("https://www.ys39.com","yeskpd","a123456")
    # r = Reptilian("http://www.yw32.com", "yeskpd", "a123456")
    r.loadConfigjs()
    print(r.login())



    while True:
        try:
            r.connect_wss()
        except Exception as e:
            print(e)