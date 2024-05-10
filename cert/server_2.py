import http.server
from http.server import SimpleHTTPRequestHandler
import ssl


class SimpleHTTPSRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Hello, world!')


server_address = ('127.0.0.1', 8000)
httpd = http.server.HTTPServer(server_address, SimpleHTTPSRequestHandler)
httpd.socket = ssl.SSLContext.wrap_socket(certfile=r'C:\Users\huangxiaoze\Desktop\WINTER_STADY\Python_Prj\XXAQ\cert\cert.pem', keyfile=r'C:\Users\huangxiaoze\Desktop\WINTER_STADY\Python_Prj\XXAQ\cert\key.pem')
httpd.serve_forever()
