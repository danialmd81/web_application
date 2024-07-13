import select
import socket
import threading
from scapy.all import sniff, IP, TCP, Raw


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
                """this line is for raising exception when connection is broken"""
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
                client_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM)
                client_socket.connect((self.dst_host, self.dst_port))
                self.tunnel(sock, client_socket)
            except KeyboardInterrupt:
                self.stop = True
            except TimeoutError as exp:
                pass
            except Exception as exp:
                print("Exception:", exp)


def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        # Here you would analyze the packet, potentially modify it,
        # and then need to forward it appropriately.
        # This is a non-trivial task and requires a deep understanding
        # of TCP/IP protocols and state management.
        print(packet.summary())


def start_sniffing():
    sniff(filter="tcp port 80", prn=packet_callback, store=0)


if __name__ == "__main__":
    sniff_thread = threading.Thread(target=start_sniffing)
    sniff_thread.start()
    # TODO:change destonation ip
    tcp_bridge = TCPBridge("0.0.0.0", 8082, "192.168.1.1", 80)
    tcp_bridge.run()
