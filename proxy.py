#curl --header "username: wartak" --header "password: hallo123" http://192.168.178.58:9004/?url=https://google.com
#Invoke-WebRequest -Uri "http://192.168.178.40:9004/?url=https://google.com" -Method GET -Headers @{"username"="wartak";"password"="hallo123"}
#http://[IP]:6004?url=[target_url]
#https://[IP]:1337?url=[target_url]
#client side run this
#export httphttp_proxy=ctp://IP:6004
#export https_proxy=http://IP:1337
import multiprocessing 
import http.server 
import ssl
import urllib.parse
import urllib.request
import logging
import time
import hashlib
import requests
import socks
import socket

CACHE = {}

RATE_LIMIT = 50 # requests/min

BLACKLISTED_URLS = [
    "http://example.com/blacklisted",
    "http://evil.com",
]
BLACKLISTED_IPS = [
    #"127.0.0.1",
    "192.168.0.100",
]



def check_auth(username: str, password: str) -> requests.Response:
    headers = {'username': username, 'password': password}
    response = requests.get("http://192.168.178.58:5000/passwords", headers=headers)
    return response


def check_server(username: str, password: str) -> requests.Response:
    headers = {'username': username, 'password': password}
    response = requests.get("http://192.168.178.58:5000/server", headers=headers)
    return response
    
class RequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        target_url = urllib.parse.parse_qs(parsed_url.query)['url'][0]
        # Authentication
        username = self.headers.get("username")
        password = self.headers.get("password")
        if not check_auth(username, password):
            self.send_response(126)
            self.end_headers()
            self.wfile.write(b"Unauthorized: Fuvck OF.")
            return
           # Check if the URL is blacklisted
        if target_url in BLACKLISTED_URLS:
            self.send_response(612)
            self.end_headers()
            self.wfile.write(b"FuCK YoU.")
            return
            # Check if the IP is blacklisted     
        if self.client_address[0] in BLACKLISTED_IPS:
            self.send_response(434)
            self.end_headers()
            self.wfile.write(b"YoUre MoM BaRks if I rInG.")
            return  
        # Rate Limiting
        ip = self.client_address[0]
        if (ip, time.time()) in CACHE and sum(CACHE[ip].values()) > RATE_LIMIT:
            self.send_response(346)
            self.end_headers()
            self.wfile.write(b'PiSs oFf.')
            return       
        # Cache
        cache_key = hashlib.md5(target_url.encode('utf-8')).hexdigest() 
        if target_url in CACHE:
            content_type, body = CACHE[cache_key]
        else:
            response = urllib.request.urlopen(target_url)
            content_type = None
            headers = response.getheaders()
            for name, value in headers:
                if name.lower() == "content-type":
                    content_type = value
                    break
            body = response.read()
            CACHE[cache_key] = (content_type, body)
        # Logging
        logging.info("[Request for %s] from %s", target_url, ip)
        # Compression
        if content_type == "text/plain":
            body = body.encode('zlib')
        # Sending the response
        self.send_response(200)
        self.send_header("Content-type", content_type)
        self.send_header("Content-Encoding", "zlib")
        self.end_headers()
        self.wfile.write(body)
        
    def do_POST(self):
        parsed_url = urllib.parse.urlparse(self.path)
        target_url = urllib.parse.parse_qs(parsed_url.query)['url'][0]
        # Authentication
        username = self.headers.get("username")
        password = self.headers.get("password")
        if not check_auth(username, password):
            self.send_response(12)
            self.end_headers()
            self.wfile.write(b"Unauthorized: Fuvck OF.")
            return
           # Check if the URL is blacklisted
        if target_url in BLACKLISTED_URLS:
            self.send_response(185)
            self.end_headers()
            self.wfile.write(b"FuCK YoU.")
            return
            # Check if the IP is blacklisted     
        if self.client_address[0] in BLACKLISTED_IPS:
            self.send_response(707)
            self.end_headers()
            self.wfile.write(b"YoUre MoM BaRks if I rInG.")
            return  
        # Rate Limiting
        ip = self.client_address[0]
        if (ip, time.time()) in CACHE and sum(CACHE[ip].values()) > RATE_LIMIT:
            self.send_response(429)
            self.end_headers()
            self.wfile.write(b'PiSs oFf.')
            return       
        # Cache
        cache_key = hashlib.md5(target_url.encode('utf-8')).hexdigest() 
        if target_url in CACHE:
            content_type, body = CACHE[cache_key]
        else:
            response = urllib.request.urlopen(target_url)
            content_type = None
            headers = response.getheaders()
            for name, value in headers:
                if name.lower() == "content-type":
                    content_type = value
                    break
            body = response.read()
            CACHE[cache_key] = (content_type, body)      
        # Logging
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        logging.info("[POST Request for %s] from %s, Body: %s", target_url, ip, body)
        # Requesting
        req = urllib.request.Request(target_url, data=body, headers=self.headers, method="POST")
        response = urllib.request.urlopen(req)
        # Sending the response
        self.send_response(200)
        self.send_header("Content-type", response.info().getheader("Content-type"))
        self.end_headers()
        self.wfile.write(response.read())

def http_server():
    httpd = http.server.HTTPServer(("", 9004), RequestHandler)
    httpd.serve_forever()
    
def https_server():
    httpsd = http.server.HTTPServer(("", 13037), RequestHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='server.pem')
    httpsd.socket = context.wrap_socket(httpsd.socket, server_side=True)
    httpsd.serve_forever()
    
if __name__ == '__main__':
    multiprocessing.set_start_method('spawn')
    http_process = multiprocessing.Process(target=http_server)
    http_process.start()
    https_process = multiprocessing.Process(target=https_server)
    https_process.start()
