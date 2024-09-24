"""
Heavily assisted by and modified from code found from an unknown source on Telegram
with the following credit:
 * @Author: passby
 * @Date: 2020-07-23 00:16:29 
"""
import base64
import binascii
import datetime
import hashlib
import json
import logging
import os
import re
import select
import socket

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from passlib.hash import md5_crypt

import asyncio

logger = logging.getLogger(__name__)



"""
    Create a WhatsminerAccessToken for each ASIC you want to control and then pass the
    token to the WhatsminerAPI classmethods.

    Basic flow:

    token1 = WhatsminerAccessToken(ip_address="1.2.3.4", admin_password="xxxx")
    token2 = WhatsminerAccessToken(ip_address="1.2.3.5", admin_password="xxxx")

    # Read-only checks
    WhatsminerAPI.get_read_only_info(token1, "status")
    WhatsminerAPI.get_read_only_info(token2, "status")

    # Writeable API
    WhatsminerAPI.exec_command(token1, "power_off", additional_params={"respbefore": "true"})
"""


class WhatsminerAccessToken:
    """ Reusable token to access and/or control a single Whatsminer ASIC.
        Token will renew itself as needed if it expires.
    """
    def __init__(self, ip_address: str, port: int = 4028, admin_password: str = None):
        # Create a read-only access token with just ip_address.
        # Create a read and write access token with ip_address and admin_password
        self.created = datetime.datetime.now()
        self.ip_address = ip_address
        self.port = port
        self._admin_password = admin_password

        if self._admin_password:
            self._initialize_write_access()


    def _initialize_write_access(self):
        """
        Encryption algorithm:
        Ciphertext = aes256(plaintext)，ECB mode
        Encode text = base64(ciphertext)

        (1)api_cmd = token,$sign|api_str    # api_str is API command plaintext
        (2)enc_str = aes256(api_cmd, $key)  # ECB mode
        (3)tran_str = base64(enc_str)

        Final assembly: enc|base64(aes256("token,sign|set_led|auto", $aeskey))
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.ip_address, self.port))
                s.sendall('{"cmd": "get_token"}'.encode('utf-8'))
                data = recv_all(s, 4000)

            token_info = json.loads(data)["Msg"]
            if token_info == "over max connect":
                raise Exception(data)

            # Make the encrypted key from the admin password and the salt
            pwd = crypt(self._admin_password, "$1$" + token_info["salt"] + '$')
            pwd = pwd.split('$')
            key = pwd[3]

            # Make the aeskey from the key computed above and prep the AES cipher
            aeskey = hashlib.sha256(key.encode()).hexdigest()
            aeskey = binascii.unhexlify(aeskey.encode())
            self.cipher = AES.new(aeskey, AES.MODE_ECB)

            # Make the 'sign' that is passed in as 'token'
            tmp = crypt(pwd[3] + token_info["time"], "$1$" + token_info["newsalt"] + '$')
            tmp = tmp.split('$')
            self.sign = tmp[3]

            self.created = datetime.datetime.now()
        except Exception as e:
            logger.error(f"Failed to initialize write access: {e}")

    def enable_write_access(self, admin_password: str):
        self._admin_password = admin_password
        self._initialize_write_access()


    def has_write_access(self):
        """ Checks write access and refreshes token, if necessary. """
        if not self._admin_password:
            return False

        if (datetime.datetime.now() - self.created).total_seconds() > 30 * 60:
            # writeable token has expired; reinitialize
            self._initialize_write_access(self._admin_password)

        return True


class WhatsminerAPI:
    @classmethod
    async def get_multiple_read_only_info(cls, access_token: WhatsminerAccessToken, commands: list):
        reader = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(access_token.ip_address, access_token.port), 5)
            results = []
            for cmd in commands:
                json_cmd = {"cmd": cmd}
                writer.write(json.dumps(json_cmd).encode('utf-8') + b'\n')
                await writer.drain()
                
                data = await asyncio.wait_for(cls.recv_all(reader), 5)
                if data:
                    try:
                        result = json.loads(data.decode())
                        results.append(result)
                    except json.JSONDecodeError:
                        results.append({"error": f"Invalid JSON for command {cmd}", "raw_data": data.decode()})
                else:
                    results.append({"error": f"No data received for command {cmd}"})
                
                # Add a small delay between commands
                await asyncio.sleep(0.1)
            
            return results
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

    @staticmethod
    async def recv_all(reader):
        data = bytearray()
        while True:
            try:
                chunk = await reader.read(1024)
                if not chunk:
                    break
                data.extend(chunk)
                if b'\n' in chunk:
                    break
            except asyncio.TimeoutError:
                break
        return bytes(data)
    
    @classmethod
    async def get_read_only_info(cls, access_token: WhatsminerAccessToken, cmd: str, additional_params: dict = None):
        """ Send READ-ONLY API command asynchronously.
        """
        json_cmd = {"cmd": cmd}
        if additional_params:
            json_cmd.update(additional_params)

        reader = None
        writer = None
        try:
            # Attempt to open a connection with a timeout
            reader, writer = await asyncio.wait_for(asyncio.open_connection(access_token.ip_address, access_token.port), 5)
            writer.write(json.dumps(json_cmd).encode('utf-8'))
            await writer.drain()
            # Data reception with a timeout
            data = await asyncio.wait_for(cls.recv_all(reader, 4000), 5)
            try:
                return json.loads(data.decode())
            except json.JSONDecodeError:
                raise ValueError("Received data is not valid JSON")
        except asyncio.TimeoutError as e:
            raise asyncio.TimeoutError(f"Timeout occurred: {str(e)}") from None
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            if reader is not None:
                await reader.read(0)  # Recommended way to close the StreamReader




    @classmethod
    async def get_multiple_read_only_info(cls, access_token: WhatsminerAccessToken, commands: list):
        reader = None
        writer = None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(access_token.ip_address, access_token.port), 5)
            results = []
            for cmd in commands:
                json_cmd = {"cmd": cmd}
                writer.write(json.dumps(json_cmd).encode('utf-8'))
                await writer.drain()
                data = await asyncio.wait_for(cls.recv_all(reader, 4000), 5)
                results.append(json.loads(data.decode()))
            return results
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            if reader is not None:
                await reader.read(0)


    @classmethod
    async def exec_command(cls, access_token: WhatsminerAccessToken, cmd: str, additional_params: dict = None):
        """ Send WRITEABLE API command asynchronously.

            e.g. await WhatsminerAPI.exec_command(access_token, cmd="power_off", additional_params={"respbefore": "true"})

            Returns: json response
        """
        if not access_token.has_write_access():
            raise Exception("access_token must have write access")

        # Encrypt it and assemble the transport json
        enc_str = base64.encodebytes(access_token.cipher.encrypt(cls.add_to_16(json.dumps({
            "cmd": cmd, "token": access_token.sign, **(additional_params or {})
        })))).decode('utf8').replace('\n', '')

        api_packet_str = json.dumps({'enc': 1, 'data': enc_str})


        reader, writer = await asyncio.wait_for(asyncio.open_connection(access_token.ip_address, access_token.port), 5)  # 5-second timeout
        try:
            writer.write(api_packet_str.encode())
            await writer.drain()
            data = await asyncio.wait_for(cls.recv_all(reader, 4000), 5)  # 5-second timeout
            json_response = json.loads(data.decode())


            if "STATUS" in json_response and json_response["STATUS"] == "E":
                logger.error(json_response["Msg"])
                raise Exception(json_response["Msg"])

            resp_ciphertext = base64.b64decode(json_response["enc"])
            resp_plaintext = access_token.cipher.decrypt(resp_ciphertext).decode().rstrip("\x00")
            resp = json.loads(resp_plaintext)
            return resp
        except asyncio.TimeoutError:
            logger.exception("Connection timed out")
            raise
        except Exception as e:
            logger.exception("Error decoding encrypted response")
            raise e
        finally:
            writer.close()
            await writer.wait_closed()

    @staticmethod
    async def recv_all(reader, n):
        data = bytearray()
        while len(data) < n:
            packet = await reader.read(n - len(data))
            if not packet:
                break
            data.extend(packet)
        return data

    @staticmethod
    def add_to_16(s):
        return str.encode(s + '\0' * ((16 - len(s) % 16) % 16))



# ================================ misc helpers ================================
def crypt(word, salt):
    standard_salt = re.compile('\s*\$(\d+)\$([\w\./]*)\$')
    match = standard_salt.match(salt)
    if not match:
        raise ValueError("salt format is not correct")
    extra_str = match.group(2)
    result = md5_crypt.hash(word, salt=extra_str)
    return result



# Adapted from: https://stackoverflow.com/a/17668009
def recv_all(sock, n):
    # Helper function to recv n bytes
    sock.setblocking(True)
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            if data:
                return data
            return None
        data.extend(packet)
    return data