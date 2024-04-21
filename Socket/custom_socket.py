from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM, SocketKind, error as socket_error
from threading import Thread
from select import select
from typing import Optional
from Protocol_Handler.protocol_constants import ProtoConsts
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger


class CustomSocket(Thread):
    """Handles all the required logic and functionality of a multi-threaded Socket."""

    def __init__(self, connection_protocol: str, debug_mode: bool) -> None:
        super().__init__()
        self.connection_protocol = connection_protocol
        self.debug_mode = debug_mode

    def set_socket_protocol(self) -> SocketKind:
        """Sets transport protocol to TCP or UDP."""
        if self.connection_protocol.lower() == ProtoConsts.PROTO_TCP:
            return SOCK_STREAM
        elif self.connection_protocol.lower() == ProtoConsts.PROTO_UDP:
            return SOCK_DGRAM
        else:
            raise ValueError(f"Unsupported connection protocol '{self.connection_protocol}'.")

    def create_socket(self) -> socket:
        """Creates a custom socket object."""
        try:
            protocol = self.set_socket_protocol()
            custom_socket = socket(AF_INET, protocol)

            # For dev mode
            if self.debug_mode:
                print(f"Created custom socket {custom_socket} successfully.")

            return custom_socket

        except socket_error as e:
            raise CustomException(error_msg=f"Unable to create socket.", exception=e)

    def connect(self, sck: socket, ip_address: str, port: int) -> None:
        """Setups the Msg Server as a client in order to register to Authentication server."""
        try:
            sck.connect((ip_address, port))

            # For dev mode
            if self.debug_mode:
                print(f"Connected to {ip_address}:{port}")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to connect to {ip_address}:{port}", exception=e)

    def monitor_connection(self, sck: socket) -> bool:
        """Returns True if the given socket is open, False otherwise."""
        try:
            # Use select to check if the socket is readable
            _, writeable, _ = select([], [sck], [], 0)
            return bool(writeable)

        # Socket is closed
        except socket_error:
            # For dev mode
            if self.debug_mode:
                print(f"{ProtoConsts.CONSOLE_ERROR} Socket {sck.getpeername()} is closed.")
            return False

    def receive_packet(self, sck: socket, receive_buffer: Optional[int] = 1024, logger: Optional[Logger] = None) -> bytes:
        """Main receive method, return a raw packet for unpacking purposes."""
        try:
            received_data = b''
            while True:
                chunk = sck.recv(receive_buffer)
                if not chunk:
                    break
                received_data += chunk

                msg = f"Received packet of length {len(received_data)} successfully."
                if logger:
                    logger.logger.debug(msg=msg)

                # For dev mode
                if self.debug_mode:
                    print(msg)

                return received_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to receive packet from {sck.getpeername()}.", exception=e)

    def send_packet(self, sck: socket, packet: bytes, logger: Optional[Logger] = None) -> None:
        """Main send method."""
        try:
            sck.send(packet)

            # For fev mode
            msg = f"Sent packet of length {len(packet)} successfully."
            if logger:
                logger.logger.debug(msg=msg)

            if self.debug_mode:
                print(msg)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to send packet to {sck.getpeername()}.", exception=e)

    def send_recv_packet(self, sck: socket, packet: bytes, buffer_size: Optional[int] = 1024,
                         logger: Optional[Logger] = None, response: Optional[bool] = False) -> bytes:
        """Sends and Receives using class send and receive main methods."""
        try:
            self.send_packet(sck=sck, packet=packet, logger=logger)

            if response:
                return self.receive_packet(sck=sck, receive_buffer=buffer_size, logger=logger)

        except Exception as e:
            raise CustomException(error_msg=f"Send-Recv Error.", exception=e)
