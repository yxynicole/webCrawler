#!/usr/bin/env python

# Project 2: Web Crawler
# CS 5700 - Fall 2020
# https://david.choffnes.com/classes/cs4700fa20/project2.php
# Project Team: Xinyu Ye and Jeff Taylor
# See README for more information

import socket, re, sys
HOST = 'cs5700fa20.ccs.neu.edu'
PORT = 80
NEW_LINE = '\r\n'

Cookies = []
Cache = {}
Visited = set()
Frontier = set()
Flags = set()

def connection():
    # Create and return a TCP connetion with target hostname and port number
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.SOL_TCP)
    s.connect((HOST, PORT))
    return s

def send(message):
    conn = connection()
    try:
        # make sure the sending message is encoded into byte string
        if hasattr(message, 'encode'): message = message.encode('utf-8')
        conn.sendall(message)
        # make sure the received message is always unicode
        resp = conn.recv(2 ** 16).decode('utf-8')
        return resp
    finally:
        # always close connection afterwards
        conn.close()

def login(username, password):
    url = '/accounts/login/'
    # first get token from login page
    _, headers, _ = get(url)
    set_cookie(headers)

    # 4 parameters below are required in the login POST request body
    body = '&'.join([
        'username=%s' % username,
        'password=%s' % password,
        'csrfmiddlewaretoken=%s' % Cache['csrftoken'],# the csrftoken is cached in set_cookie() function
        'next=/fakebook/'
    ])
    message = NEW_LINE.join([
        'POST %s HTTP 1.1' % url,
        'Host: cs5700fa20.ccs.neu.edu',
        'Content-Length: %d' % len(body),
        'Content-Type: application/x-www-form-urlencoded',
        'Connection: keep-alive'] + Cookies[-1:] + [ # add cookie in the header
        '', # empty line is required between body and headers        
        body,
        '',
    ])

    resp = send(message)
    # return 302 if login is successful  
    if not resp.startswith('HTTP/1.1 302 FOUND'):
        print(resp.split('\n', 1)[0].strip())
        exit(1)
    headers, content = parse_response(resp)
    set_cookie(headers)

def get(url):
    # Sending GET request against the url 
    # returns status code, response header and response body
    message = NEW_LINE.join(['GET %s HTTP/1.1' % url, 
        'Host: %s' % HOST, 
        'Connection: keep-alive'] + Cookies[-1:] + ['',''] # cookie will be set if any
    )
    resp = send(message)
    first_line = resp.split('\n')[0]
    status = first_line.strip().split(' ', 2)[1] #Maxsplit = 2
# break the raw message into headers and response body
    headers, content = parse_response(resp)

    return status, headers, content
   
def parse_response(resp):
    resp = re.sub('\r', '', resp) # remove all the '\r'
    # get the end of the first line; there are always two empty lines between header and body
    a, b = resp.index('\n')+1, resp.index('\n' * 2)
    headers = [
        tuple(i.split(':', 1)) # pair of header name and value
        for i in resp[a:b].split('\n')
    ]
    content = resp[b:]
    return headers, content

def set_cookie(headers):
    # Actively looking for Set cookie header and cache the value of sessionid and csrftoken 
    for h in headers:
        if 'Set-Cookie' in h: 
            if 'csrftoken=' in h[1]:
                Cache['csrftoken'] = h[1].split('=')[1].split(';')[0]
            if 'sessionid=':
                Cache['sessionid'] = h[1].split('=')[1].split(';')[0]
            Cookies.append('Cookie: csrftoken=%s; sessionid=%s' % (Cache['csrftoken'], Cache['sessionid']))

def handle_response(status, headers, content):
    # Takes in status code, headers, and content (html) and returns True when status code
    # is successfully handled (status codes 200, 302, 301, 403 & 404), and False
    # if status code is 500.  If status code is 200, handles the response by adding
    # unvisisted profiles on the page to the frontier and scanning the page for secret flags

    if status == '200':
        add_unvisited_profiles_to_frontier(content)
        scan_for_secret_flags(content)
        return True

    elif status == '302' or status == '301':
        direct_to = dict(headers)['Location']
        status_new, headers_new, content_new = get(direct_to[direct_to.index(HOST) + len(HOST):])
        return handle_response(status_new, headers_new, content_new) # handle_response returns a boolean

    elif status == '403' or status == '404':
        return True #abandoning and not doing any processing

    elif status == '500':
        return False

    else:
        sys.exit("Unexpected status code") 
    
def add_unvisited_profiles_to_frontier(html):
    # Scans the page for /fakebook/ urls and adds them to the frontier if they
    # have not already been visited
    fakebook_urls = re.findall(r'href=[\'"]?(/fakebook/[^\'">]+)', html)
    for url in fakebook_urls:
        if url not in Visited:
            Frontier.add(url)

def scan_for_secret_flags(html):
    # Scans html for the secret flag identifier and adds any found flags
    # to the Flags set

    secret_flag_identifier = '<h2 class=\'secret_flag\' style=\"color:red\">FLAG: '
    
    #Can handle the case if there are multiple flags on one page
    for flag in re.finditer(secret_flag_identifier, html):
        secret_id_start_index = flag.end()
        Flags.add(html[secret_id_start_index : secret_id_start_index + 64])

if __name__ == '__main__':
    username, password = sys.argv[1], sys.argv[2]
    login(username, password)

    Frontier.add('/fakebook/')
    while len(Flags) < 5 and len(Frontier) > 0:
        profile = Frontier.pop()
        status, headers, content = get(profile)
        success = handle_response(status, headers, content)
        if success:
            Visited.add(profile)
        else:
            # Handle_response only returns false in event status if 500
                # if 500 is returned, then put the link back into the queue and pick it up later
            Frontier.add(profile) 
    for flag in Flags:
        print(flag)
