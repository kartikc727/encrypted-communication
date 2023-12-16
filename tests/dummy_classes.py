class DummyPubKeyServer:
    def register(self, user):
        ...

    def __call__(self, username)->bytes:
        return b'DummyPubKey'
    
class DummyNetwork:
    def connect(self, user):
        ...

    def send_message(self, message):
        ...

    @property
    def latest_message(self)->str:
        return 'DummyLatestMessage'
    
class DummyUser:
    def __init__(self, username, pks, network):
        self._username = username

    @property
    def username(self)->str:
        return self._username
    
    @property
    def public_key(self)->bytes:
        return b'DummyPublicKey'
    
    @property
    def current_time(self)->str:
        return 'DummyCurrentTime'
    
    def create_session(self, recipient_username:str):
        ...

    def send(self, payload, recipient_username:str):
        ...

    def send_raw(self, message):
        ...

    def receive(self, message)->int:
        return 0
