from ftplib import FTP
from ftplib import all_errors
import configparser
import os
import sys


def dostuff(config_file):
    config = configparser.ConfigParser()
    config.read(config_file)
    host = config.get("Main", "Ftp Server")
    username = config.get("Main", "Ftp User")
    password = config.get("Main", "Ftp Password")

    ftp = FTP(host, timeout=300)
    ftp.login(username, password)

    repfile = config.get("Main", "Outbound") + "/" + config.get("Main", "Host") + ".REP"

    i = 1

    while True:
        exists = os.path.isfile(repfile)
        if exists:
            file = open(repfile, "rb")
            ftp.storbinary("STOR " + config.get("Main", "Host") + ".REP", file)
            file.close()
            os.remove(repfile)
            print("SENT: " + config.get("Main", "Host") + ".REP")
            repfile = config.get("Main", "Outbound") + "/" + config.get("Main", "Host") + ".REP." + str(i)
            i = i + 1
        else:
            break

    qwkfile = config.get("Main", "Inbound") + "/" + config.get("Main", "Host") + ".QWK"
    with open(qwkfile, 'wb') as file:
        def callback(data):
            file.write(data)

        try:
            ftp.retrbinary("RETR " + config.get("Main", "Host") + ".QWK", callback)
            file.close()
            print("RETREIVED: " + config.get("Main", "Host") + ".QWK")
        except all_errors:
            file.close()
            os.remove(qwkfile)
        

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage python qwknetftpc.py config.ini")
        exit(1)

    server = dostuff(sys.argv[1])
