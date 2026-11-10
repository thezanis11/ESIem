"""Tiny deterministic services/probes for isolated Linux network acceptance."""
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import socket
import socketserver
import urllib.request


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["http", "echo", "probe-http", "probe-echo"])
    parser.add_argument("address")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--path", default="/")
    args = parser.parse_args()
    if args.mode == "http":
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b"ESIem isolated lab\n"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        HTTPServer((args.address, args.port), Handler).serve_forever()
    elif args.mode == "echo":
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(3)
                self.request.sendall(self.request.recv(128))
        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
        Server((args.address, args.port), Handler).serve_forever()
    else:
        try:
            if args.mode == "probe-http":
                # No proxy from the runner may bypass these isolated routes.
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f"http://{args.address}:{args.port}{args.path}", timeout=3) as response:
                    assert response.status == 200 and b"ESIem" in response.read()
            else:
                with socket.create_connection((args.address, args.port), timeout=3) as sock:
                    sock.sendall(b"ESIem telemetry test")
                    assert sock.recv(128) == b"ESIem telemetry test"
            print(json.dumps({"connected": True}))
        except (OSError, AssertionError) as error:
            print(json.dumps({"connected": False, "reason": type(error).__name__}))
            raise SystemExit(1)


if __name__ == "__main__":
    main()
