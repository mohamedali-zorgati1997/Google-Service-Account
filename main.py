from serviceaccount import ServiceAccount
from tokenauth import ServiceAccountAuth

from json import load
from os import chdir
from os.path import split
from requests import get
from traceback import print_exc

#I use this for testing environment where all the files are in one directory
#I make sure the current directory is the file directory
chdir(split(__file__)[0]) if split(__file__)[0] else None

upload_url = 'https://www.googleapis.com/upload/drive/v3/'
api_url = 'https://www.googleapis.com/drive/v3/'
scopes = ['https://www.googleapis.com/auth/drive']

SA = ServiceAccount(load(open('SA.json')))
SA.setScopes(scopes)
SA.readAT('AT_SA.pkl')

auth = ServiceAccountAuth(SA)

try:
    
    params = {
        'fields': 'storageQuota/limit, storageQuota/usage'
    }
    resp = get(api_url + 'about', params=params, auth=auth)
    print(resp.status_code)
    storage = resp.json()['storageQuota']
    usage = int ((int(storage['usage']) / int(storage['limit'])) * 40)
    print('[' + '|' * usage + ' ' * (40 - usage) + ']' + '{}/{}'.format(storage['usage'], storage['limit']))
except :
    print_exc()
finally:
    SA.saveAT('AT_SA.pkl')
