# www.theforage.com - Telstra Cyber Task 3
# Firewall Server Handler

from http.server import BaseHTTPRequestHandler, HTTPServer
import re

host = "localhost"
port = 8000

class ServerHandler(BaseHTTPRequestHandler):

    def block_request(self):
         self.send_error(403, "Request blocked due to firewall")

    def handle_request(self):

        def rule_1():  # Blocking POST request to /tomcatwar.jsp
            if (self.command == "POST" and
                self.path == "/tomcatwar.jsp" and
                self.headers.get("Host") == "nbn.external.hostname"):
                self.block_request()
                return True
            return False

        def rule_2(): #Blocking headers
            if (self.headers.get("suffix") == "%>//" and
                self.headers.get("C1") == "Runtime" and
                self.headers.get("C2") == "<%" and
                self.headers.get("DNT") == "1" and
                self.headers.get("Content-Type") == "application/x-www-form-urlencoded"):
                self.block_request() 
                return True
            return False

        if rule_1() or rule_2():#Conditions
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"message": "Success"}')

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

if __name__ == "__main__":
    server = HTTPServer((host, port), ServerHandler)
    print("[+] Firewall Server")
    print("[+] HTTP Web Server running on: %s:%s" % (host, port))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

    server.server_close()
    print("[+] Server terminated. Exiting...")
    exit(0)