#!/usr/bin/python3
# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import os
import re
from urllib.parse import urlencode

import requests


class Yubico(object):
    def __init__(self, client_id, secret_key):
        self.client_id = client_id
        self.secret_key = base64.b64decode(secret_key.encode('ascii'))

    @staticmethod
    def _bytes(s):
        if isinstance(s, str):
            return s.encode('utf-8')
        elif isinstance(s, bytes):
            return s
        else:
            raise TypeError(f"Invalid argument {s}")

    def __query__(self, otp, nonce):
        data = [
            ('id', self.client_id),
            ('otp', otp),
            ('nonce', nonce)
        ]
        query = urlencode(data)
        signature = self.__signature__(query)
        query += f"&h={signature.replace('+', '%2B')}"
        return query

    def __signature__(self, query):
        pairs = query.split('&')
        pairs = [pair.split('=', 1) for pair in pairs]
        pairs_sorted = sorted(pairs)
        pairs_string = '&'.join(['='.join(pair) for pair in pairs_sorted])

        digest = hmac.new(self.secret_key, self._bytes(pairs_string), hashlib.sha1).digest()
        signature = base64.b64encode(digest).decode('utf-8')

        return signature

    @staticmethod
    def __request__(query):
        url = 'https://api.yubico.com/wsapi/2.0/verify'
        headers = {
            'User-Agent': 'yubico-client'
        }
        response = requests.get(url=url, params=query, headers=headers)
        if response.status_code == 200:
            return response.text

    @staticmethod
    def __verify__(response):
        pattern = re.compile(r'status=([A-Z0-9_]+)')
        status = pattern.findall(response)
        return status[0] if status else None

    def verify(self, otp):
        rand_bytes = self._bytes(os.urandom(30))
        nonce = base64.b64encode(rand_bytes, self._bytes('xz'))[:25].decode('utf-8')
        query = self.__query__(otp, nonce)
        response = self.__request__(query)
        status = self.__verify__(response)
        return True if status == 'OK' else False


if __name__ == "__main__":
    yubico = Yubico("90684", "BuBMH7MSKQw3FxPuoi5FBDW6hmE=")
    print(yubico.verify(input("otp: ")))
