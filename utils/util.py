# -*- coding: utf-8 -*-
"""
-------------------------------------------------
   File Name：     util
   Description :
   Author :       Administrator
   date：          2018-10-08
-------------------------------------------------
   Change Activity:
                   2018-10-08:
-------------------------------------------------
"""
__author__ = 'Sto'
import hashlib
from urllib import parse
import random
import time
class CodeUtils(object):
    """
    编码工具类
    """

    @staticmethod
    def md5(text):
        """
        MD5 加密
        :param text: 需要加密的字符串 
        :return:  返回加密后的32位结果
        """
        m2 = hashlib.md5()
        m2.update(text.encode())
        return m2.hexdigest()

    @staticmethod
    def url_encode(text):
        """
        url编码
        :param text:需要编码的字符串 
        :return:  返回编码后的字符串
        """
        return parse.quote(text)


class TextUtils(object):
    """
    文本工具类
    """
    @staticmethod
    def getRandomLetter(num):
        """
        获取随机字母
        :return: 
        """
        d = "abcdefghijklmnopqrstuvwxyz";
        str1 = ""
        for _ in range(num):
            str1 += random.choice(d)
        return str1

    """
       字符串工具类
       """

    @staticmethod
    def isEmpty(val):
        """
        判断字符串是否为空
        :param val: 需要判断的字符串
        :return:  空返回True 否者为 False
        """
        return val == None or val == ""

    @staticmethod
    def getTextMiddle(val, head, tail, index=0):
        """
        取文本中间
        :param val:  原文本
        :param head: 左边文本
        :param tail: 右边文本
        :param index: 起始索引 默认为0
        :return:  返回取到的值，如果取值不存在 返回 None 或 “”
        """
        if TextUtils.isEmpty(val):
            return None
        if len(val) < index:
            return None
        val = val[index:]
        startIndex = val.find(head)
        if startIndex == -1:
            return None
        if startIndex >= 0:
            startIndex += len(head)
        endIndex = val.find(tail, startIndex)
        if endIndex == -1:
            return None
        return val[startIndex:endIndex]


class Time_utils(object):
    """
        时间处理工具类
    """

    @staticmethod
    def getNowTimeNum():
        """
        获取当前时间戳 13位
        :return: 
        """
        return str(int(round(time.time() * 1000)))


class Date_utils(object):

    @staticmethod
    def getNowDateStr(format=None):
        """
        获取现行时间的指定格式字符串
        :param format: 
        :return: 
        """
        if TextUtils.isEmpty(format):
            format = "%Y-%m-%d %H:%M:%S"
        now = int(time.time())
        timeStruct = time.localtime(now)
        return time.strftime(format, timeStruct)

if __name__ == '__main__':
    print(Date_utils.getNowDateStr("%H:%M:%S"))