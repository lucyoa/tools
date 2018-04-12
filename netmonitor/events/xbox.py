from monitor.event import Event


class Event(Event):
    def trigger(self, event, asset):
        if event is "appeared" and "xbox" in asset.hostname.lower():
            return True

        return False
    
    def execute(self):
        self.exec("touch /tmp/xbox")
