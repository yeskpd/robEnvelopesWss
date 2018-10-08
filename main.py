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
from funCore import Reptilian

# 设置任务队列 (队列是为后期加web对接定制的。)
task_Queue = queue.Queue(1000)
list_user = [] # 全局账号列表，主要用于使用

def startUpUserWork(r):
   """
    账号工作，调用账号登录
   :param r: 
   :return: 
   """
   r.is_login_work = True  # 标记这个类正在执行登录工作，避免重复线程启动

   for _ in range(50):
       try:
           r.loadConfigjs() # 登录地址
           r.login() # 登录账号

           # 登录成功,使用线程开始连接wss
           threading.Thread(target=r.connect_wss).start()
           break # 结束本次登录
       except Exception as e:
           msg = str(e)
           if msg.find("密码") != -1:
               break
           time.sleep(20) # 延时20秒后继续登录

   r.is_login_work = False # 放开，表示没有在登录工作




def startUp():
    """
    启动队列
    :return: 
    """
    while True:
        # 得到一个任务
        r = task_Queue.get()
        list_user.append(r)  # 加入账号列表
        # 使用线程处理登录
        t = threading.Thread(target=startUpUserWork, args=(r,))
        t.start()





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
        t = threading.Thread(target=startUpUserWork, args=(r,)).start()

    r.is_login_work = False

def heartbeat():
    """
    心跳
    :return: 
    """
    while True:
        time.sleep(30) # 30秒检查一次账号状态
        for r in list_user:
            if not r.is_accord_heartbeat():
                continue # 不符合心跳，换一个
            # 使用线程来心跳，有的会网络堵塞，为了不避免后面的账号出现太大延时
            # t = threading.Thread(target=heartbeatWork, args=(r,)).start()
            heartbeatWork(r)

if __name__ == '__main__':
    # 启动监控队列
    threading.Thread(target=startUp).start()
    # 开始载入本地数据
    loadTextUser("./userList.txt")
    # 打开账号心跳
    heartbeat()


