"""
ipTIME Firmware Fuzzer - Mock Target Server
퍼저 테스트를 위한 가짜 타겟 서버
UDP, HTTP, UPnP 포트를 열고 간단한 응답을 제공
"""

import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# 설정
HOST = "127.0.0.1"
UDP_PORT = 9999
HTTP_PORT = 8080  # 권한 문제로 80 대신 8080 사용
UPNP_PORT = 5000
SSDP_PORT = 1900


class MockUDPHandler:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((HOST, UDP_PORT))
        self.running = True
        print(f"[Mock] UDP Server listening on {HOST}:{UDP_PORT}")

    def run(self):
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                if not data:
                    continue

                # 간단한 응답 로직
                if b"EFUD" in data:
                    # ipTIME 프로토콜 흉내
                    resp = b"EFUD" + b"\x00\x02" + b"\x00\x08" + b"MOCK_OK\x00"
                    self.sock.sendto(resp, addr)
                    print(f"[Mock] UDP from {addr}: {data[:20]}...")
            except Exception as e:
                if self.running:
                    print(f"[Mock] UDP Error: {e}")

    def stop(self):
        self.running = False
        self.sock.close()


class MockHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>iPTIME Mock</h1></body></html>")
        # print(f"[Mock] HTTP GET {self.path}")

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        body = self.rfile.read(content_length)

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")
        # print(f"[Mock] HTTP POST {self.path} ({len(body)} bytes)")

    def log_message(self, format, *args):
        pass  # 로그 노이즈 제거


class MockUPnPHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # SOAP 요청 처리
        self.send_response(200)
        self.send_header("Content-type", "text/xml")
        self.end_headers()
        response = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
  <s:Body>
    <u:Response>OK</u:Response>
  </s:Body>
</s:Envelope>"""
        self.wfile.write(response.encode())
        # print(f"[Mock] UPnP POST {self.path}")

    def log_message(self, format, *args):
        pass


def run_http_server():
    server = HTTPServer((HOST, HTTP_PORT), MockHTTPHandler)
    print(f"[Mock] HTTP Server listening on {HOST}:{HTTP_PORT}")
    server.serve_forever()


def run_upnp_server():
    server = HTTPServer((HOST, UPNP_PORT), MockUPnPHandler)
    print(f"[Mock] UPnP Server listening on {HOST}:{UPNP_PORT}")
    server.serve_forever()


if __name__ == "__main__":
    print("Starting Mock Servers...")

    # UDP 실행
    udp_server = MockUDPHandler()
    t_udp = threading.Thread(target=udp_server.run)
    t_udp.daemon = True
    t_udp.start()

    # HTTP 실행
    t_http = threading.Thread(target=run_http_server)
    t_http.daemon = True
    t_http.start()

    # UPnP 실행
    t_upnp = threading.Thread(target=run_upnp_server)
    t_upnp.daemon = True
    t_upnp.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping Mock Servers...")
        udp_server.stop()
