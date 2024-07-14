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

    def __init__(self, host, port, dst_host, dst_port):
        self.host = host
        self.port = port
        self.dst_host = dst_host
        self.dst_port = dst_port

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(1)
        self.server.bind((self.host, self.port))
        self.stop = False

    @threaded
    def tunnel(self, sock: socket.socket, sock2: socket.socket, chunk_size=1024):
        try:
            while not self.stop:
                # this line is for raising exception when connection is broken
                sock.getpeername() and sock2.getpeername()
                r, w, x = select.select([sock, sock2], [], [], 1000)
                if sock in r:
                    data = sock.recv(chunk_size)
                    if len(data) == 0:
                        break
                    sock2.sendall(data)

                if sock2 in r:
                    data = sock2.recv(chunk_size)
                    if len(data) == 0:
                        break
                    sock.sendall(data)
        except:
            pass
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
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.dst_host, self.dst_port))
                self.tunnel(sock, client_socket)
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
        print(f"HTTP Path: {http_layer.Path.decode('utf-8')}")
        print(f"HTTP User-Agent: {http_layer.User_Agent.decode('utf-8')}")
        print(f"HTTP Accept: {http_layer.Accept.decode('utf-8')}")
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            ip_layer = packet.getlayer(IP)
            print(
                f"Source IP: {ip_layer.src}:{tcp_layer.sport} --> Destination IP: {ip_layer.dst}:{tcp_layer.dport}"
            )


if __name__ == "__main__":
    # sniff(filter="tcp", prn=packet_handler)
    # Create a new thread for running the sniffing function
    sniff_thread = threading.Thread(
        target=sniff,
        kwargs={"filter": "tcp port 80", "prn": http_packet_callback, "store": False},
    )

    # Start the thread
    sniff_thread.start()
    tcp_bridge = TCPBridge("0.0.0.0", 8080, "192.168.44.130", 80)
    tcp_bridge.run()
