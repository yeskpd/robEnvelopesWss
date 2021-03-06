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

import time
import threading
import queue
from funCore import Reptilian,config

# 设置任务队列 (队列是为后期加web对接定制的。)
task_Queue = queue.Queue(config.get("threadNum",100))
list_user = [] # 全局账号列表，主要用于使用心跳

def startUpUserWork(r):
   """
    账号工作，调用账号登录
   :param r: 
   :return: 
   """
   r.is_login_work = True  # 标记这个类正在执行登录工作，避免重复线程启动
   try:
       r.loadConfigjs() # 登录地址
       r.login() # 登录账号

       # 连接wss，不能直接掉调用这个方法会卡主，直到断开或者异常
       threading.Thread(target=r.connect_wss).start()
       time.sleep(2) # 延时好了。

   except Exception as e:
       # 错误了，线程维护登录程序！(主要是释放这个账号等的登录线程，让出队列线程空位。)
       threading.Thread(target=startUpUserWorkFor, args=(r,)).start()
   else:
       # 没有报错
       r.is_login_work = False # 放开，表示没有在登录工作


def startUpUserWorkFor(r):
    """
    登录失败以后使用一个线程在这里维护继续登录。
    :param r: 
    :return: 
    """
    r.is_login_work = True  # 标记这个类正在执行登录工作，避免重复线程启动

    for _ in range(50):
        r.is_login_work = True
        try:
            r.loadConfigjs()  # 登录地址
            r.login()  # 登录账号

            # 登录成功,使用线程开始连接wss
            threading.Thread(target=r.connect_wss).start()
            break  # 结束本次登录
        except Exception as e:
            msg = str(e)
            if msg.find("密码") != -1:
                break
            time.sleep(config.get("loginErrTime",60))  # 延时20秒后继续登录

    r.is_login_work = False  # 放开，表示没有在登录工作



def startUp():
    """
    启动队列
    :return: 
    """
    while True:
        # 得到一个任务
        r = task_Queue.get()
        list_user.append(r)  # 加入账号列表
        startUpUserWork(r) # 单线程登录，登录失败会自动开启多线程维护




def loadTextUser(filePath):
    """
    加载本地数据
    :param filePath: 
    :return: 
    """
    with open(filePath,encoding="utf-8") as f:
        while True:
            line = f.readline()
            if not line:
                break
            line = line.strip("\n")
            print(line)
            arr = line.split("----")
            if len(arr) >= 3:
                r = Reptilian(arr[0],arr[1],arr[2])
                task_Queue.put(r) # 加入到队列

def heartbeatWork(r):

    r.is_login_work = True  # 标记这个类正在执行登录工作，避免重复线程启动

    if not r.user_heartbeat() or not r.is_connect():
        # 账号掉线 或 没有连接，使用线程继续登录
        t = threading.Thread(target=startUpUserWorkFor, args=(r,)).start()
    else:
        # 账号正常，释放
        r.is_login_work = False

def heartbeat():
    """
    心跳
    :return: 
    """
    while True:
        time.sleep(config.get("heartbeatTime",30)) # 30秒检查一次账号状态
        for r in list_user:
            if not r.is_accord_heartbeat():
                continue # 不符合心跳，换一个
            # 使用线程来心跳，有的会网络堵塞，为了不避免后面的账号出现太大延时
            t = threading.Thread(target=heartbeatWork, args=(r,)).start()
            # heartbeatWork(r)

if __name__ == '__main__':
    # 启动监控队列，这里最大开启20个线程即可
    for _ in range(config.get("threadNum",20)):
        threading.Thread(target=startUp).start()

    # 开始载入本地数据
    loadTextUser(config.get("loadTextUserPath","./userList.txt"))
    # 打开账号心跳
    heartbeat()


