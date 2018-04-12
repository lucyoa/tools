import subprocess


class Event(object):
    def exec(self, cmd):
        subprocess.Popen(cmd.split(" "))
