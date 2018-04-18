import sys
from monitor.event import Event


class Event(Event):
    def __init__(self):
        self.opened = False

    def trigger(self, event, asset):
        return False

        if not self.opened and event is "appeared":
            self.opened = True
            return True

        return False
    
    def execute(self):
        if sys.platform == "darwin":
            client = "open"
        else:
            client = "sensible-browser"

        cmd = "{} https://www.youtube.com/watch?v=dQw4w9WgXcQ".format(client)
        self.exec(cmd)
