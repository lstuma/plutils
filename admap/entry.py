from plutils.log import Logger
import plutils.log as pl_log

log = Logger(__name__, color="#aaaaff")

def main():
    from rich import print
    log.info("Starting AD Map - Tests")
    log.error("test")
    from admap.core import ActiveDirectory
    username = "ADMINISTRATOR.HTB\\olivia"
    password = "ichliebedich"
    server = "administrator.htb"
    active_directory = ActiveDirectory(server, username, password)
    active_directory.test()
