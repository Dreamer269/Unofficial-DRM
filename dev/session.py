import logging
from media.stagefright import MediaErrors
from utils import String8
from Session import Session
from AesCtrDecryptor import AesCtrDecryptor
from InitDataParser import InitDataParser
from JsonWebKey import JsonWebKey

class clearkeydrm:
    def __init__(self):
        self.mMapLock = threading.Lock()
        self.mKeyMap = {}

    def getKeyRequest(self, initData, mimeType):
        parser = InitDataParser()
        return parser.parse(initData, mimeType)

    def provideKeyResponse(self, response):
        responseString = response.decode('utf-8')
        keys = {}
        with self.mMapLock:
            parser = JsonWebKey()
            if parser.extractKeysFromJsonWebKeySet(responseString, keys):
                for keyId, key in keys.items():
                    self.mKeyMap[keyId] = key
                return MediaErrors.OK
            else:
                return MediaErrors.ERROR_DRM_UNKNOWN

    def decrypt(self, keyId, iv, source, subSamples):
        with self.mMapLock:
            keyIdVector = bytearray(keyId)
            if keyIdVector not in self.mKeyMap:
                return MediaErrors.ERROR_DRM_NO_LICENSE
            key = self.mKeyMap[keyIdVector]
            decryptor = AesCtrDecryptor()
            return decryptor.decrypt(key, iv, source, subSamples)
