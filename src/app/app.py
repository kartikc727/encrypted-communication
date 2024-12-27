import time
from threading import Thread, Event
from .client import CommunicationClient
from .constants import EXIT_MESSAGE
from .ui import ChatUI, MessageElement

# TODO: App has single chat, UI is session-based. Fix this.

class ChatComplete(Exception):
  ...


class CommunicationApp:
  def __init__(self, client: CommunicationClient, ui: ChatUI):
    self._client = client
    self._ui = ui
    self._ui.set_app(self)
    self._receive_thread = Thread(name='Fake message thread',
                                  target=self.fake_receive_message,
                                  daemon=True)
    self._exit = Event()

  def receive_message(self, message: str, sender: str):
    elem = MessageElement(message, sender=sender)
    self._ui.add_message(elem)

  def fake_receive_message(self):
    while not self._exit.is_set():
      self.receive_message('Fake message', 'Bob')
      time.sleep(2)

  def send_message(self, message: str, receiver: str) -> bool:
    if message == EXIT_MESSAGE:
      self.cleanup()
      return True
    
    elem = MessageElement(message, is_self=True)
    self._ui.add_message(elem)
    
    # actual sending logic would go here
    ...

    return False

  def cleanup(self):
    self._exit.set()
    self._receive_thread.join()

  def start(self):
    print(f'Starting app with client {self._client.name}\n')
    self._receive_thread.start()
    
    try:
      self._ui.run()
    except ChatComplete:
      print('Chat complete. Exiting...')
    # finally:
    #   self.cleanup()
    #   print('App closed.')
