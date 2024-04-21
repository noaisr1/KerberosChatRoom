from sys import exit as sys_exit
from struct import unpack, calcsize
from Utils.utils import fetch_entry_from_json_db
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Utils.logger import Logger, CustomFilter
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Socket.custom_socket import socket, Thread
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import server_request, server_response, packet_no_payload
from Server.server_interface import ServerInterface
from Server.MsgServer.msg_server_constants import ram_service_template, MsgConsts
from Server.MsgServer.service_registration_handler import RegistrationHandler
from Server.MsgServer.service_symmetric_key_handler import SymmetricKeyHandler


class MsgServerCore(ServerInterface):
    """Handles the Msg Server core functionalities."""

    def __init__(self, connection_protocol: str, ip_address: str, port: int, service_name: str, is_registered: bool, debug_mode: bool) -> None:
        super().__init__(connection_protocol, ip_address, port, debug_mode)
        self.ip_address = ip_address
        self.port = port
        self.service_name = service_name
        self.is_registered = is_registered
        self.debug_mode = debug_mode
        self.connections_list = []
        self.threads = []
        self.active_connections = 0
        self.client_socket = self.custom_socket.create_socket()
        self.service_socket = self.custom_socket.create_socket()
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.registration_handler = RegistrationHandler(debug_mode=debug_mode)
        self.symmetric_key_handler = SymmetricKeyHandler(debug_mode=debug_mode)

    def setup_as_client(self) -> None:
        """Setups the Msg Server as a client in order to register to AS."""
        try:
            self.custom_socket.connect(sck=self.client_socket, ip_address=self.ip_address, port=self.port)
            self.logger.logger.info(f"Connected to {self.ip_address}:{self.port} successfully.")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to setup {self.__class__.__name__} as client", exception=e)

    def handle_peer(self, sck: socket, ram_template: dict) -> None:
        """Starts the Chat Room."""
        try:
            # Insert new connection
            self.add_new_connection(sck=sck,
                                    connections_list=self.connections_list,
                                    active_connections=self.active_connections)

            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"{sck.getpeername()} has entered the chat."
            self.logger.logger.info(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(f"{ProtoConsts.CONSOLE_ACK} {msg}")

            # Start chat
            while True:

                # Monitor peers connections
                if not self.custom_socket.monitor_connection(sck=sck):
                    self.cleanup(sck=sck,
                                 connections_list=self.connections_list,
                                 active_connections=self.active_connections)

                # Receive encrypted message request
                msg_request = self.custom_socket.receive_packet(sck=sck, logger=self.logger)

                # Peer has disconnected
                if not msg_request:
                    break

                # Adjust sizes to get encrypted message content
                msg_formatter = self.protocol_handler.build_packet_format(code=ProtoConsts.PKT_ENC_MSG_WITHOUT_CONTENT,
                                                                          formatter=server_request.copy())
                msg_fmt = self.protocol_handler.generate_packet_fmt(raw_packet=msg_formatter)
                msg_content_size = len(msg_request[calcsize(msg_fmt):])

                # Unpack encrypted message packet
                unpacked_msg_request = unpack(f"{msg_fmt}{msg_content_size}s", msg_request)
                client_id, version, code, payload_size, msg_size, msg_iv, msg_content = unpacked_msg_request

                # Fetch and validate service AES key
                aes_key = ram_template[MsgConsts.RAM_KDC_AES_KEY]
                Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=aes_key)

                # Decrypt message and print to screen
                decrypted_msg = self.encryptor.decrypt(encrypted_value=msg_content,
                                                       decryption_key=aes_key,
                                                       iv=msg_iv).decode()
                print(decrypted_msg)

                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_MSG_ACK
                packed_msg_ack = self.protocol_handler.pack_request(code=ProtoConsts.RES_AES_KEY_ACK,
                                                                    data=packet_no_payload,
                                                                    formatter=server_response.copy())
                self.custom_socket.send_packet(sck=sck, packet=packed_msg_ack, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle client {sck.getpeername()}.", exception=e)    

    def setup_as_chat_room(self, service_ram_template: dict) -> None:
        """Setups Msg Server as a Server that receives requests from Clients."""
        try:
            # Get DNS mapping from RAM
            self.ip_address = service_ram_template[MsgConsts.RAM_IP_ADDRESS]
            self.port = service_ram_template[MsgConsts.RAM_PORT]

            # Initialize Server
            self.setup_server(sck=self.service_socket)

            # Print welcome message
            print(MsgConsts.WELCOME_MSG.format(MsgConsts.MSG_SERVER_LOGO, service_ram_template[MsgConsts.RAM_SERVICE_NAME]))

            # For dev mode
            if self.debug_mode:
                print(f"{ProtoConsts.CONSOLE_ACK} Starting Server...")
                print(f"{ProtoConsts.CONSOLE_ACK} Server is now listening on {self.ip_address}:{self.port}")

            # Wait for clients requests
            while True:
                connection, address = self.service_socket.accept()

                # For dev mode
                if self.debug_mode:
                    print(f"{ProtoConsts.CONSOLE_ACK} Connected to peer {connection.getpeername()}")

                # Handle Symmetric Key requests from clients
                if self.symmetric_key_handler.handle_symmetric_key_request(sck=self.custom_socket,
                                                                           client_socket=connection,
                                                                           ram_template=service_ram_template,
                                                                           encryptor=self.encryptor,
                                                                           protocol_handler=self.protocol_handler):

                    # For dev mode
                    if self.debug_mode:
                        print(f"Chat Room service template --> {service_ram_template}")

                    # Assign new thread to each connected client and enter chat mode
                    client_thread = Thread(target=self.handle_peer, args=(connection, service_ram_template))
                    client_thread.start()
                    self.threads.append(client_thread)

                # Return general error
                else:
                    packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_GENERAL_ERROR
                    packed_general_error = self.protocol_handler.pack_request(code=ProtoConsts.RES_GENERAL_ERROR,
                                                                              data=packet_no_payload,
                                                                              formatter=server_response.copy())
                    self.custom_socket.send_packet(sck=connection, packet=packed_general_error, logger=self.logger)

        except Exception as e:
            self.logger.logger.error(str(e))

            # Cleanup
            self.service_socket.close()
            for thread in self.threads:
                thread.join()

            raise CustomException(error_msg=f"Unable to run {self.__class__.__name__}.", exception=e)

    def run(self) -> None:
        """Msg Server main run method."""

        # Create service RAM template and update its values
        service_ram_template = ram_service_template.copy()
        service_ram_template[MsgConsts.RAM_SERVICE_NAME] = self.service_name
        Validator.validate_injection(data_type=ValConsts.FMT_NAME, value_to_validate=self.service_name)

        # Registered Service
        if self.is_registered:

            # Fetch data from file DB and update RAM DB
            service_entry = fetch_entry_from_json_db(file_path=MsgConsts.SERVICE_POOL_FILE_PATH,
                                                     pivot_key=MsgConsts.RAM_SERVICE_NAME,
                                                     pivot_value=self.service_name)

            service_aes_key = service_entry[MsgConsts.RAM_SERVICE_AES_KEY_ENCODED]
            service_ram_template[MsgConsts.RAM_SERVICE_AES_KEY_ENCODED] = service_aes_key
            service_server_id = service_entry[MsgConsts.RAM_SERVICE_ID_HEX]
            if isinstance(service_aes_key, str):
                service_entry[MsgConsts.RAM_SERVICE_AES_KEY] = Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY,
                                                                                            value_to_validate=service_aes_key)
            if isinstance(service_server_id, str):
                service_entry[MsgConsts.RAM_SERVICE_ID] = Validator.validate_injection(data_type=ValConsts.FMT_ID,
                                                                                       value_to_validate=service_server_id)
            service_ram_template.update(service_entry)

            # For dev mode
            if self.debug_mode:
                print(f"Parsed service template --> {service_ram_template}")

            # Start default service
            self.setup_as_chat_room(service_ram_template=service_ram_template)

        # Not a registered Service
        else:
            # Setup first as a client
            self.setup_as_client()

            # Register
            if not self.registration_handler.handle_registration_request(sck=self.custom_socket,
                                                                         client_socket=self.client_socket,
                                                                         ram_template=service_ram_template,
                                                                         service_name=self.service_name,
                                                                         encryptor=self.encryptor,
                                                                         protocol_handler=self.protocol_handler):

                print(f"{ProtoConsts.CONSOLE_FAIL} Register to Auth server has failed, shutting down")
                self.client_socket.close()
                sys_exit(ProtoConsts.STATUS_ERROR_CODE)

            # For dev mode
            if self.debug_mode:
                print(f"Registered service template --> {service_ram_template}")

            # Initialize Server as a service only on registration success
            self.setup_as_chat_room(service_ram_template=service_ram_template)








