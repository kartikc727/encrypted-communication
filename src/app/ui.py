import curses
import time
import queue
from threading import Thread, Event

from . import constants


class MessageElement:
  def __init__(self, message: str, *, is_self: bool = False,
               sender: str = None):
    self._is_self = is_self
    self._sender = constants.SELF_NAME if is_self else sender
    self._message = message

  def make_elems(self)-> tuple:
    elems = []
    color = constants.SELF_COLOR if self._is_self else constants.OTHER_COLOR
    
    elems.append((self._sender+' ', color[0]))
    elems.append((constants.ARROW_CHAR+' ', constants.ARROW_COLOR[0]))
    elems.append((self._message+'\n',None))
    
    return tuple(elems)


class ChatUI:
  def __init__(self):
    self._message_queue = queue.Queue()
    self._exit = Event()
    self._chat_thread = None
    self._type_thread = None
    self._app = None

  def _set_colors(self):
    curses.start_color()
    for color_cfg in (constants.SELF_COLOR, constants.OTHER_COLOR,
                      constants.ARROW_COLOR):
      curses.init_pair(*color_cfg)
  
  def _chatting_loop(self, win):
    while not self._exit.is_set():
      try:
        elem = self._message_queue.get(block=True, timeout=1)
        for msg_str, color_num in elem.make_elems():
          if color_num is not None:
            win.addstr(msg_str, curses.color_pair(color_num))
          else:
            win.addstr(msg_str)
        win.refresh()
      except queue.Empty:
        ...
  
  def _typing_loop(self, win):
    while not self._exit.is_set():
      win.erase()
      win.addstr(constants.ARROW_CHAR+' ', constants.ARROW_COLOR[0])
      win.refresh()
      input_str = win.getstr().decode('utf-8')
      done = self._app.send_message(input_str, 'Bob')
      if done:
        self._exit.set()

  def _main(self, stdscr):
    # set up the screen
    print('Setting up screen')
    stdscr.clear()
    self._set_colors()
    curses.curs_set(1)

    # create windows
    win_chat = curses.newwin(curses.LINES - 3, curses.COLS, 0, 0)
    win_type = curses.newwin(3, curses.COLS, curses.LINES - 3, 0)
    win_chat.scrollok(True)
    win_type.scrollok(True)

    # start the main loop to send messages
    print('Startin threads')
    self._chat_thread = Thread(name='Chatting thread',
                               target=self._chatting_loop,
                               daemon=True,
                               args=(win_chat,))
    self._chat_thread.start()
    self._type_thread = Thread(name='Typing thread',
                               target=self._typing_loop,
                               daemon=True,
                               args=(win_type,))
    self._type_thread.start()

    # wait for the threads to finish
    self._chat_thread.join()
    self._type_thread.join()

  def set_app(self, app):
    self._app = app

  def add_message(self, message: MessageElement):
    self._message_queue.put(message)

  def run(self):
    print('Running UI')
    try:
      # Initialize curses
      stdscr = curses.initscr()
      self._main(stdscr)
    finally:
      ...
