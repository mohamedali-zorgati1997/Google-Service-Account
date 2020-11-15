from requests.auth import AuthBase

class ServiceAccountAuth(AuthBase):
    """Add authorization header required to authenticate a Service Account"""
    def __init__(self, serviceAccount):
        self.SA = serviceAccount

    def __call__(self, r):
        r.headers['Authorization'] = 'Bearer ' + self.SA.getAccessToken()
        return r



