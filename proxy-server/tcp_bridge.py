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

    # def __init__(self, host, port, dst_host, dst_port):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        # self.dst_host = dst_host
        # self.dst_port = dst_port

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
                    return header.split(": ")[1]
        except UnicodeDecodeError:
            pass
        return None

    # @threaded
    # def tunnel(
    #     self,
    #     sock: socket.socket,
    #     sock2: socket.socket,
    #     chunk_size=1024,
    #     specific_host="13.13.13.13",
    # ):
    @threaded
    def tunnel(
        self,
        sock: socket.socket,
        chunk_size=1024,
        specific_host="13.13.13.13",
    ):
        try:
            while not self.stop:
                sock.getpeername()
                r, w, x = select.select(sock, [], [], 1000)
                if sock in r:
                    data = sock.recv(chunk_size)
                    if len(data) == 0:
                        break
                    host = self.parse_http_request(data)
                    # if host == specific_host:
                    #     print(sock.getpeername(), ":", sock2.getpeername(), ":", host)
                    #     sock2.sendall(data)
                    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock2.connect((host, 80))

                if sock2 in r:
                    data = sock2.recv(chunk_size)
                    if len(data) == 0:
                        break
                    # Assuming you only want to filter requests, not responses
                    sock.sendall(data)
        except:
            pass
        finally:
            try:
                sock2.close()
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
                # client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # client_socket.connect((self.dst_host, self.dst_port))
                # self.tunnel(sock, client_socket)
                self.tunnel(sock)
            except KeyboardInterrupt:
                self.stop = True
            except TimeoutError as exp:
                pass
            except Exception as exp:
                print("Exception:", exp)


if __name__ == "__main__":
    # tcp_bridge = TCPBridge("0.0.0.0", 8080, "192.168.44.130", 80)
    tcp_bridge = TCPBridge("0.0.0.0", 8080)
    tcp_bridge.run()
