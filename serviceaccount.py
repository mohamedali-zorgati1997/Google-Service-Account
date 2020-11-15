from time import time
from base64 import urlsafe_b64encode
from json import dumps
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from requests import post
from pickle import dump, load

class ServiceAccount:
    def __init__(self, SA_json):

        self.SA = SA_json
        self.scopes = []
        self.__AT = []

    def setScopes(self, scopes):
        """
        save scopes for future use
        :param scopes: iterable containing the scopes of the claim
        """
        if scopes:
            self.scopes = scopes

    def getJWTHeader(self):
        # the JWT header has the same form in all cases so we are making it constant
        return b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"

    def getJWTClaim(self):
        """generate a JWT Claim you must call setScopes before
        :return: a dict object containing the necessary JWT claim fields
        :rtype: dict
        """
        if self.scopes:
            claim = {
                'iss': self.SA['client_email'],
                'scope': " ".join(self.scopes),
                'aud': self.SA['token_uri'],
                'iat': int(time())
            }
            claim['exp'] = claim['iat'] + 3600
            return claim

    def getJWT(self, header=None, claim=None):
        """
        generate JWT using provided header and claim or using class functions
        :param header: a bytes-like object of the base64 encoded (urlsafe) JWT header
        :param claim: a bytes-like object representing the json dump of the claim dict
        :return: bytes-like object of the JWT needed to obtain an access token
        :rtype: bytes
        """
        message = []
        if header:
            message.append(header)
        else :
            message.append(self.getJWTHeader())
        if claim:
            message.append(urlsafe_b64encode(claim).strip(b'='))
        else :
            message.append(urlsafe_b64encode(
                dumps(self.getJWTClaim()).encode()
            ).strip(b'='))

        pkey = RSA.import_key(self.SA['private_key'])
        msg_hash = SHA256.new(b".".join(message))
        message.append(urlsafe_b64encode(
            pkcs1_15.new(pkey).sign(msg_hash)
        ).strip(b'='))
        return b'.'.join(message)

    def obtainAccessToken(self, JWT=None):
        print("Obtaining new Access Token ...")
        if not JWT:
            JWT = self.getJWT()

        data = {
            'grant_type': "urn:ietf:params:oauth:grant-type:jwt-bearer",
            'assertion': JWT
        }
        resp = post(self.SA['token_uri'], data)
        resp_json = resp.json()

        if 'access_token' in resp_json:
            return [resp_json['access_token'], resp_json['expires_in']]
        else:
            print('Failed to obtain token. Verify scopes and/or service account kson file')

    def getAccessToken(self):
        """
        get Access Token string
        :return: Access Token
        :rtype: str
        """
        if self.__AT:
            if int(time()) < self.__AT[1]:
                return self.__AT[0]
        self.__AT = self.obtainAccessToken()
        self.__AT[1] += int(time())
        return self.__AT[0]

    def saveAT(self, filename):
        """
        save Access Token in a file for future use
        :param filename: the name of the file to save into
        """
        dump(self.__AT, open(filename, 'wb'))

    def readAT(self, filename):
        """
        read Access Token from a previously saved file using saveAT
        :param filename: the name of the file to read from
        """
        try:
            self.__AT  = load(open(filename, 'rb'))
        except FileNotFoundError:
            self.__AT = []



