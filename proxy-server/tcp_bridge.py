import select
import socket
from struct import pack
import threading
from scapy.all import sniff, IP, TCP, sendp, Raw, send
from scapy.layers.http import HTTP, HTTPRequest  # Import the HTTP layer


def threaded(fn):
    def wrapper(*args, **kwargs):
        _thread = threading.Thread(target=fn, args=args, kwargs=kwargs)
        _thread.start()
        return _thread

    return wrapper


class TCPBridge(object):

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(1)
        self.server.bind((self.host, self.port))
        self.stop = False

    def parse_http_request(self, data):
        try:
            headers = data.decode("utf-8").split("\r\n")
            for header in headers:
                if header.startswith("Host:"):
                    return header.split(": ")[1], header.split(":")[2]
        except UnicodeDecodeError:
            pass
        return None

    @threaded
    def tunnel(
        self,
        sock: socket.socket,
        chunk_size=1024,
    ):
        try:
            while not self.stop:
                sock.getpeername()
                r, w, x = select.select(sock, [], [], 1000)
                if sock in r:
                    data = sock.recv(chunk_size)
                    if len(data) == 0:
                        break
                    host, port = self.parse_http_request(data)
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    client_socket.connect(host, port)
                    client_socket.sendall(data)

                if client_socket in r:
                    data = client_socket.recv(chunk_size)
                    if len(data) == 0:
                        break
                    # Assuming you only want to filter requests, not responses
                    sock.sendall(data)
        except:
            pass
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                sock.close()
            except:
                pass

    def run(self) -> None:

        self.server.listen()

        while not self.stop:
            try:
                (sock, addr) = self.server.accept()
                if sock is None:
                    continue
                self.tunnel(sock)
            except KeyboardInterrupt:
                self.stop = True
            except TimeoutError as exp:
                pass
            except Exception as exp:
                print("Exception:", exp)


def http_packet_callback(packet):
    if packet.haslayer(HTTPRequest):
        http_layer = packet.getlayer(HTTPRequest)
        print(f"HTTP Method: {http_layer.Method.decode('utf-8')}")
        print(f"HTTP Host: {http_layer.Host.decode('utf-8')}")
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            ip_layer = packet.getlayer(IP)
            print(
                f"Source IP: {ip_layer.src}:{tcp_layer.sport} --> Destination IP: {ip_layer.dst}:{tcp_layer.dport}"
            )


if __name__ == "__main__":
    tcp_bridge = TCPBridge("0.0.0.0", 8080)
    tcp_bridge.run()
