# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     log
   Description :
   Author :       Administrator
   date：          2018-10-08
-------------------------------------------------
   Change Activity:
                   2018-10-08:
-------------------------------------------------
"""
__author__ = 'Sto'

class Logs(object):

    def __init__(self,saveFile):
        self.file = open(saveFile,"a+",encoding="utf-8")


    def y(self,data):
        """
        原样记录
        :param data: 
        :return: 
        """
        self.file.write(data+"\n")
        self.file.flush()



    def __del__(self):
        # 关闭文件
        self.file.close()