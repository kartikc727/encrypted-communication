""" User class for the encrypted communication system. """

import logging
import time
import secrets
from datetime import datetime, timedelta
from threading import Thread
import queue
from termcolor import colored

from .helpers import Network, PubKeyServer, MultiKeyDict
from .encryption import CryptoManager

class User:
    """
    Represents a user in the encrypted communication system.

    Attributes:
        REQUEST_TIMEOUT_MS (int):
            The timeout for message requests in milliseconds.
        SESSION_MESSAGE_PRIORITY (int):
            The priority for session-related messages.
        OTHER_MESSAGE_PRIORITY (int):
            The priority for other messages.
        STOP_THREAD_PRIORITY (int):
            The priority for the stop sentinel.
        DT_FMT (str):
            The date-time format used for timestamping messages.
        STOP_THREAD_SENTINEL (object):
            The sentinel used to stop threads.
    """

    REQUEST_TIMEOUT_MS = 5000
    SESSION_MESSAGE_PRIORITY = 5
    OTHER_MESSAGE_PRIORITY = 1
    STOP_THREAD_PRIORITY = 10
    STOP_THREAD_SENTINEL = object()
    DT_FMT = '%Y%m%d-%H%M%S.%f'

    def __init__(self, username:str, pks:PubKeyServer, network:Network,
            start:bool=True):
        """Initializes the user. User gets registered with the public key server and connects to the network.

        Args:
            username (str):
                Unique user ID.
            pks (PubKeyServer):
                Public key server where the user will register their public key and get other users' public keys.
            network (Network):
                Network where the user will send and receive messages.
            start (bool, optional):
                Whether to start the user immediately. If False, the user will need to be started manually. Defaults to True.
        """
        # Our unique User ID
        self._username = username

        # Network related items
        self._network = network
        self._network.connect(self)

        # Encryption related items
        self._private_key, self._public_key = CryptoManager.gen_key_pair()
        self._cm = CryptoManager()

        # Identity related items
        self._pks = pks
        self._pks.register(self)

        # Sending messages
        self._outgoing_message_queue = queue.PriorityQueue()
        self._message_send_thread = None

        # Processing incoming messages
        self._incoming_message_queue = queue.Queue()
        self._message_receive_thread = None

        # Session related items
        # TODO: Thread safety
        self._active_outgoing_requests = MultiKeyDict('username', 'nonce')
        self._active_incoming_requests = MultiKeyDict('username', 'responder_nonce')
        self._active_sessions = MultiKeyDict('username', 'session_id')

        # Attaching session info to messages
        self._session_waiting_queue = queue.PriorityQueue()
        self._message_packing_thread = None

        self._user_active = False
        if start:
            self.start()

    @property
    def username(self)->str:
        """Unique user ID."""
        return self._username

    @property
    def public_key(self)->bytes:
        """Public key of the user."""
        return self._public_key

    def start(self):
        """Starts the user. After starting, the user can send and receive messages.

        Raises:
            RuntimeError:
                If the user is already active.
            RuntimeError:
                If the user is currently in the process of being activated.
        """
        if self._user_active is None:
            raise RuntimeError(f'User "{self._username}" currently in activation/deactivation process.')
        if self._user_active:
            raise RuntimeError(f'User "{self._username}" already active.')
        
        print(colored(f'Starting user "{self._username}"...', 'blue'))
        self._user_active = None

        self._message_send_thread = Thread(
            name = f'Message sending thread for user "{self._username}"',
            target = self._message_send_loop,
            daemon = True)
        self._message_send_thread.start()

        self._message_receive_thread = Thread(
            name = f'Message receiving thread for user "{self._username}"',
            target = self._message_process_loop,
            daemon = True)
        self._message_receive_thread.start()

        self._message_packing_thread = Thread(
            name = f'Message packing thread for user "{self._username}"',
            target = self._message_packing_loop,
            daemon = True)
        self._message_packing_thread.start()

        self._user_active = True
        print(colored(f'User "{self._username}" started.\n', 'green'))

    def stop(self):
        """Stops the user. After stopping, the user cannot send or receive messages.

        Raises:
            RuntimeError:
                If the user is already inactive.
            RuntimeError:
                If the user is currently in the process of being deactivated.
        """
        if self._user_active is None:
            raise RuntimeError(f'User "{self._username}" currently in activation/deactivation process.')
        if not self._user_active:
            raise RuntimeError(f'User "{self._username}" already inactive.')
        
        self._user_active = None
        print(colored(f'Trying to gracefully stop user "{self._username}"...', 'blue'))
        self._outgoing_message_queue.put((
            self.STOP_THREAD_PRIORITY,
            self.STOP_THREAD_SENTINEL))
        self._incoming_message_queue.put(
            self.STOP_THREAD_SENTINEL)
        self._session_waiting_queue.put((
            self.STOP_THREAD_PRIORITY, None,
            self.STOP_THREAD_SENTINEL))
        
        self._message_send_thread.join()
        self._message_send_thread = None

        self._message_receive_thread.join()
        self._message_receive_thread = None

        self._message_packing_thread.join()
        self._message_packing_thread = None
        
        self._user_active = False
        print(colored(f'User "{self._username}" stopped.', 'green'))

    def _send_payload(self, payload, priority:int, recipient_username:str):
        encrypted_msg, encrypted_key = self._encrypt_message(payload, recipient_username)

        packaged_payload = {
            'header' : {
                'sender' : self._username,
                'recipient' : recipient_username,
                'aes_key' : encrypted_key},
            'body' : encrypted_msg}

        self._outgoing_message_queue.put((-priority, packaged_payload))

    def create_session(self, recipient_username:str)->int:
        """Creates a session with the specified user.

        Args:
            recipient_username (str):
                The username of the user with whom to create a session.

        Raises:
            RuntimeError:
                If the user is not active.

        Returns:
            int:
                Return code.
        """
        # Check that user is active
        if not self._user_active:
            raise RuntimeError(f'User "{self._username}" is not active.')
        
        # Check if session already exists with the user
        if ('username', recipient_username) in self._active_sessions:
            return 0

        # Check if session is in the process of being created with the user
        if ('username', recipient_username) in self._active_incoming_requests:
            return 2
        if ('username', recipient_username) in self._active_incoming_requests:
            return 2

        # Start the process of creating a new session with the user
        self._send_session_request(recipient_username)

        return 2

    def _send_session_request(self, recipient_username:str):
        nonce = secrets.token_urlsafe(64)
        payload = {
            'message_type' : 'session_request',
            'content' : {'requestor_nonce' : nonce}}
        self._active_outgoing_requests.add({'username':recipient_username, 'nonce':nonce})

        self._session_waiting_queue.put((
            -self.SESSION_MESSAGE_PRIORITY, recipient_username, payload))

    def _send_session_response(self, requestor_username:str, requestor_nonce:str):
        nonce = secrets.token_urlsafe(64)
        payload = {
            'message_type' : 'session_response',
            'content' : {
                'requestor_nonce' : requestor_nonce,
                'responder_nonce' : nonce}}
        self._active_incoming_requests.add({
            'username':requestor_username,
            'requestor_nonce':requestor_nonce,
            'responder_nonce':nonce})

        self._session_waiting_queue.put((
            -self.SESSION_MESSAGE_PRIORITY,
            requestor_username, payload))

    def _send_session_info(self, requestor_nonce:str, responder_nonce:str):
        session_id = secrets.token_urlsafe(64)
        payload = {
            'message_type' : 'session_info',
            'content' : {
                'requestor_nonce' : requestor_nonce,
                'responder_nonce' : responder_nonce,
                'session_id' : session_id}}
        recipient_username = self._active_outgoing_requests['nonce', requestor_nonce]['username']
        del self._active_outgoing_requests['username', recipient_username]
        self._open_session(session_id, recipient_username)

        self._session_waiting_queue.put((
            -self.SESSION_MESSAGE_PRIORITY,
            recipient_username, payload))

    def _send_session_close_request(self, recipient_username:str):
        if ('username', recipient_username) not in self._active_sessions:
            raise KeyError(f'No session open with user: `{recipient_username}`.')

        session_id = self._active_sessions['username', recipient_username]['session_id']
        payload = {
            'message_type' : 'session_close_request',
            'content' : {
                'session_id' : session_id}}

        self._session_waiting_queue.put((
            -self.SESSION_MESSAGE_PRIORITY,
            recipient_username, payload))

    def _open_session(self, session_id:str, other_username:str):
        if ('session_id', session_id) in self._active_sessions:
            raise KeyError(f'Session with session ID: `{session_id}` already exists.')

        if ('username', other_username) in self._active_sessions:
            raise KeyError(f'Session already open with user: `{other_username}`.')

        session = {
            'session_id' : session_id,
            'username' : other_username,
            'n_messages_sent' : 0,
            'n_messages_received' : 0}

        self._active_sessions.add(session)

    def _close_session(self, session_id:str):
        if ('session_id', session_id) not in self._active_sessions:
            raise KeyError(f'No session with session ID: `{session_id}`.')

        del self._active_sessions['session_id', session_id]

    def close_session_with_user(self, other_username:str):
        """Closes the session with the specified user.

        Args:
            other_username (str):
                The username of the user with whom to close the session.

        Raises:
            RuntimeError:
                If the user is not active.
            KeyError:
                If no session exists with the specified user.
        """
        # Check that user is active
        if not self._user_active:
            raise RuntimeError(f'User "{self._username}" is not active.')
        
        if ('username', other_username) not in self._active_sessions:
            raise KeyError(f'No session open with user: `{other_username}`.')

        session_id = self._active_sessions['username', other_username]['session_id']
        self._send_session_close_request(other_username)
        self._close_session(session_id)

    def send(self, content, recipient_username:str)->int:
        """Sends a message to the specified user.

        Args:
            content (JSONType):
                The content of the message.
            recipient_username (str):
                The username of the user to whom to send the message.

        Raises:
            RuntimeError:
                If the user is not active.

        Returns:
            int:
                Return code.
        """

        # Check that user is active
        if not self._user_active:
            raise RuntimeError(f'User "{self._username}" is not active.')
        
        # Ensure we have an active session (or session request) with the recipient
        self.create_session(recipient_username)

        # Create the payload
        payload = {
            'message_type' : 'content_delivery',
            'content' : {
                'sender_content' : content}}

        # Put our message in the message queue
        self._session_waiting_queue.put((
            -self.OTHER_MESSAGE_PRIORITY,
            recipient_username, payload))
        
        return 0

    def send_raw(self, message):
        '''Function for debugging and/or simulating bad actors'''

        # Check that user is active
        if not self._user_active:
            raise RuntimeError(f'User "{self._username}" is not active.')
        
        self._network.send_message(message)

    def _message_process_loop(self):
        while True:
            try:
                message = self._incoming_message_queue.get(block=True)
                
                if message is self.STOP_THREAD_SENTINEL:
                    logging.info(f'Message receiving thread for user "{self._username}" received stop sentinel.')
                    break
                
                logging.debug(f'{self._username} processing message')
                self._process_message(message)
            
            except queue.Empty:
                continue

    def _message_send_loop(self):
        while True:
            try:
                _, packaged_payload = self._outgoing_message_queue.get(block=True)

                if packaged_payload is self.STOP_THREAD_SENTINEL:
                    logging.info(f'Message sending thread for user "{self._username}" received stop sentinel.')
                    break

                logging.debug(f'{self._username} sending message')
                self._network.send_message(packaged_payload)
            except queue.Empty:
                continue

    def _message_packing_loop(self):
        while True:
            try:
                neg_priority, recipient_username, payload = self._session_waiting_queue.get(block=True)

                if payload is self.STOP_THREAD_SENTINEL:
                    logging.info(f'Message packing thread for user "{self._username}" received stop sentinel.')
                    break

                priority = -neg_priority
                if priority < self.SESSION_MESSAGE_PRIORITY:
                    if ('username', recipient_username) in self._active_sessions:
                        session = self._active_sessions['username', recipient_username]
                        payload['session_id'] = session['session_id']
                        payload['message_id'] = session['n_messages_sent']
                        session['n_messages_sent'] += 1

                    elif ( ('username', recipient_username) in self._active_outgoing_requests or
                            ('username', recipient_username) in self._active_incoming_requests ):
                        self._session_waiting_queue.put((neg_priority, recipient_username, payload))
                        time.sleep(1)
                        continue

                    else:
                        print(colored(
                            f'\tLow priority message for recipient "{recipient_username}" waiting without session. Dropping message.\n',
                            'red'))
                        continue

                payload['certificate'] = self._sign_message(payload['content'])
                payload['timestamp'] = datetime.utcnow().strftime(self.DT_FMT)
                logging.debug(f'{self._username} packing message')
                self._send_payload(payload, priority, recipient_username)

            except queue.Empty:
                continue

    def receive(self, message)->int:
        """Receives a message from the network.

        Args:
            message (str):
                The message received from the network.
            
        Returns:
            int:
                Return code.
        """
        # Don't want to messages not sent to us
        if message['header']['recipient'] != self._username:
            return 1
        
        # Check that user is active
        if not self._user_active:
            print(colored(f'User "{self._username}" is not active. Ignoring message contents and closing communication.\n', 'red'))
            return 2

        # If message sent to us, put it in message processing queue
        self._incoming_message_queue.put(message)

        return 0

    def _get_timedelta_ms(self, timestamp_str:str)->float:
        timestamp = datetime.strptime(timestamp_str, self.DT_FMT)
        return (datetime.utcnow() - timestamp)/timedelta(milliseconds=1)

    def _process_message(self, message):
        print(colored(f'User "{self._username}" received message:', 'blue'))

        # Verify the identity of the sender
        try:
            payload = self._decrypt_message(message['body'], message['header']['aes_key'])
            content = payload['content']
            verified = self._verify_signature(content, payload['certificate'], message['header']['sender'])
            if verified:
                print(colored(f'\tSender: {message["header"]["sender"]} (verified)', 'magenta'))
            else:
                print(colored('\tCould not verify sender. Ignoring message contents and closing communication.\n', 'red'))
                return
        except ValueError:
            print(colored('\tCould not decrypt message. Ignoring message contents and closing communication.\n', 'red'))
            return

        # Verify the message is not too old
        print(colored(f'\tMessage timestamp: {payload["timestamp"]}', 'magenta'))
        td_ms = self._get_timedelta_ms(payload['timestamp'])
        if td_ms > self.REQUEST_TIMEOUT_MS:
            print(colored(f'\tMessage age: {td_ms} ms: Too old. Ignoring message contents and closing communication.\n', 'red'))
            return
        print(colored(f'\tMessage age: {td_ms} ms: Accepted.', 'magenta'))

        # Check the type of message
        if payload['message_type'] == 'session_request':
            print(colored('\tMessage type: `session_request`. Sending response.\n', 'magenta'))
            self._send_session_response(message['header']['sender'], content['requestor_nonce'])

        elif payload['message_type'] == 'session_response':
            if ('nonce', content['requestor_nonce']) not in self._active_outgoing_requests:
                print(colored('\tConnection response not recognised. Ignoring message contents and closing communication.\n', 'red'))
                return

            print(colored('\tMessage type: `session_response`. Sending session info.\n', 'magenta'))
            self._send_session_info(content['requestor_nonce'], content['responder_nonce'])

        elif payload['message_type'] == 'session_info':
            if ('responder_nonce', content['responder_nonce']) not in self._active_incoming_requests:
                print(colored('\tSession confirmation attempt without a handshake. Ignoring message contents and closing communication.\n', 'red'))
                return

            if self._active_incoming_requests['responder_nonce', content['responder_nonce']]['requestor_nonce'] != content['requestor_nonce']:
                print(colored('\tSender nonce mismatch. Ignoring message contents and closing communication.\n', 'red'))
                return

            # Everything looks good
            self._open_session(content['session_id'], message['header']['sender'])
            del self._active_incoming_requests['responder_nonce', content['responder_nonce']]
            print(colored(f'\tSession open with {message["header"]["sender"]}. Session ID: {content["session_id"][:10]}\n', 'green'))

        elif payload['message_type'] == 'content_delivery':
            if 'session_id' not in payload:
                print(colored('\tContent delivery without session ID. Ignoring message contents and closing communication.\n', 'red'))
                return
            
            session_id = payload['session_id']
            if ('session_id', session_id) not in self._active_sessions:
                print(colored(f'Invalid session ID: {content["session_id"][:10]}. Ignoring message contents and closing communication.\n', 'red'))
                return

            session = self._active_sessions['session_id', session_id]
            if session['username'] != message['header']['sender']:
                print(colored('Sender mismatch from session holder. Ignoring message contents and closing communication.\n', 'red'))
                return

            if session['n_messages_received'] != payload['message_id']:
                print(colored('Invalid message ID. Ignoring message contents and closing communication.\n', 'red'))
                return

            # Everything looks good
            session['n_messages_received'] += 1
            print(colored(f'\tVerified message: {content["sender_content"]}\n', 'green'))

        elif payload['message_type'] == 'session_close_request':
            session_id = content['session_id']
            if ('session_id', session_id) not in self._active_sessions:
                print(colored(f'Invalid session ID: {content["session_id"][:10]}. Ignoring message contents and closing communication.\n', 'red'))
                return

            session = self._active_sessions['session_id', session_id]
            if session['username'] != message['header']['sender']:
                print(colored('Sender mismatch from session holder. Ignoring message contents and closing communication.\n', 'red'))
                return

            if session['session_id'] != content['session_id']:
                print(colored('Attempting to close different session. Ignoring message contents and closing communication.\n', 'red'))
                return

            # Everything looks good
            self._close_session(session_id)
            print(colored(f'\tSession closed with {message["header"]["sender"]}. Session ID: {content["session_id"][:10]}\n', 'green'))

        else:
            print(colored('Unknown message type: {payload["message_type"]}. Ignoring message contents and closing communication.\n', 'red'))
            return

    def _encrypt_message(self, message:'JSONType', recipient_username:str)->tuple:
        return self._cm.encrypt_message(
            message, self._pks(recipient_username))

    def _decrypt_message(self, encrypted_message:str, encrypted_key:str):
        return self._cm.decrypt_message(encrypted_message, encrypted_key, self._private_key)

    def _sign_message(self, message:'JSONType'):
        return self._cm.sign_message(message, self._private_key)

    def _verify_signature(self, message:'JSONType', signature:str, author_username:str)->bool:
        return self._cm.verify_signature(
            message, signature, self._pks(author_username))
