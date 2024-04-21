from Utils import utils
from Utils.custom_exception_handler import CustomException
from Utils.logger import Logger
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_templates import packet_no_payload, code_to_payload_template, server_response
from Server.MsgServer.msg_server_constants import MsgConsts
from Server.AuthServer.kdc_registration_handler import RegistrationHandler
from Server.AuthServer.kdc_services_handler import ServicesHandler
from Server.AuthServer.kdc_key_ticket_handler import KeyTicketHandler
from Server.AuthServer.auth_server_constants import AuthConsts


class AuthServerLogic:
    """Handles all the KDC protocol requirements."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.msg_server_list = []
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)
        self.protocol_handler = ProtocolHandler(debug_mode=debug_mode)
        self.encryptor = Encryptor(debug_mode=debug_mode)
        self.registration_handler = RegistrationHandler(debug_mode=debug_mode)
        self.services_handler = ServicesHandler(debug_mode=debug_mode)
        self.key_ticket_handler = KeyTicketHandler(debug_mode=debug_mode)

    def handle_registration_request(self, server_socket: CustomSocket, client_socket: socket, request_code: int,
                                    unpacked_packet: dict, client_ram_template: dict, server_ram_template: dict) -> None:
        """Sends response with the packed register response back to the requesting peer."""
        try:
            # Handle clients requests
            if request_code == ProtoConsts.REQ_CLIENT_REG:
                register_response = self.registration_handler.register_client(data=unpacked_packet,
                                                                              client_ram_template=client_ram_template,
                                                                              encryptor=self.encryptor,
                                                                              protocol_handler=self.protocol_handler)

            # Handle servers requests
            elif request_code == ProtoConsts.REQ_SERVER_REG:
                register_response = self.registration_handler.register_service(data=unpacked_packet,
                                                                               server_ram_template=server_ram_template,
                                                                               sck=client_socket,
                                                                               msg_server_list=self.msg_server_list,
                                                                               protocol_handler=self.protocol_handler)
            else:
                raise ValueError(f"Unsupported registration request code '{request_code}'.")

            # Send response back to client/server
            server_socket.send_packet(sck=client_socket, packet=register_response, logger=self.logger)

            # For dev mode
            if self.debug_mode:
                print(f"Sent Response --> {register_response}")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle registration request from {client_socket.getpeername()}.",
                                  exception=e)

    def __send_client_is_not_registered_error(self, server_socket: CustomSocket, client_socket: socket) -> None:
        """Sends client is not registered response."""
        try:
            packet_no_payload[ProtoConsts.CODE] = ProtoConsts.PKT_NOT_REGISTERED_ERROR
            packed_client_not_registered_error = self.protocol_handler.pack_request(code=ProtoConsts.PKT_NOT_REGISTERED_ERROR,
                                                                                    data=packet_no_payload,
                                                                                    formatter=server_response.copy())
            server_socket.send_packet(sck=client_socket, packet=packed_client_not_registered_error, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to send {self.__class__.__name__} general error.", exception=e)

    def send_server_general_error(self, server_socket: CustomSocket, client_socket: socket) -> None:
        """Sends server general error response."""
        try:
            packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_GENERAL_ERROR
            packed_general_error = self.protocol_handler.pack_request(code=ProtoConsts.RES_GENERAL_ERROR,
                                                                      data=packet_no_payload,
                                                                      formatter=server_response.copy())
            server_socket.send_packet(sck=client_socket, packet=packed_general_error, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to send {self.__class__.__name__} general error.", exception=e)

    def handle_services_list_request(self, server_socket: CustomSocket, client_socket: socket, client_ram_template: dict) -> None:
        """Sends response with the packed services list back to the requesting peer."""
        try:
            # If client is not registered
            if not client_ram_template[AuthConsts.RAM_IS_REGISTERED]:
                self.__send_client_is_not_registered_error(server_socket=server_socket,
                                                           client_socket=client_socket)
            # In case of AS shutdown, get registered services from JSON DB
            if not self.msg_server_list:
                self.services_handler.get_registered_services_from_db(msg_server_list=self.msg_server_list)

            # In case of services registration process failure, Get default service
            if not self.msg_server_list and utils.is_exists(path_to_check=MsgConsts.MSG_FILE_NAME):
                self.services_handler.get_default_service_data(msg_server_list=self.msg_server_list)

            # In case Default service is not available send general error
            if not self.msg_server_list and not utils.is_exists(path_to_check=MsgConsts.MSG_FILE_NAME):
                self.send_server_general_error(server_socket=server_socket, client_socket=client_socket)

            # Get services list packed data
            packed_services_list = self.services_handler.get_services_packed_list_data(msg_server_list=self.msg_server_list,
                                                                                       protocol_handler=self.protocol_handler)
            # Create packet data frame
            data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.RES_MSG_SERVERS_LIST,
                ProtoConsts.PAYLOAD_SIZE: len(packed_services_list),
                ProtoConsts.SERVERS_LIST: packed_services_list
            }
            # # Create server list formatter template
            servers_list_formatter = code_to_payload_template[ProtoConsts.PKT_SERVERS_LIST].copy()
            servers_list_formatter.update(self.protocol_handler.update_formatter_value(formatter=servers_list_formatter,
                                                                                       pivot_key=ProtoConsts.SERVERS_LIST,
                                                                                       pivot_value=ProtoConsts.SIZE,
                                                                                       new_value=len(packed_services_list)))
            # Pack and send service list response
            packed_servers_list_response = self.protocol_handler.pack_request(code=ProtoConsts.PKT_SERVERS_LIST,
                                                                              data=data,
                                                                              formatter=server_response.copy())
            server_socket.send_packet(sck=client_socket, packet=packed_servers_list_response, logger=self.logger)

            # For dev mode
            if self.debug_mode:
                print(f"Sent Response --> {packed_servers_list_response}")

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle services list request.", exception=e)

    def handle_aes_key_request(self, server_socket: CustomSocket, client_socket: socket,
                               unpacked_packet: dict, client_ram_template: dict) -> None:
        """Sends response with the packed Encrypted Key and Ticket back to the requesting peer."""
        try:
            # If client is not registered
            if not client_ram_template[AuthConsts.RAM_IS_REGISTERED]:
                self.__send_client_is_not_registered_error(server_socket=server_socket,
                                                           client_socket=client_socket)
            # Validate received data
            client_nonce = unpacked_packet[ProtoConsts.NONCE]
            Validator.validate_injection(data_type=ValConsts.FMT_NONCE, value_to_validate=client_nonce)
            client_id = unpacked_packet[ProtoConsts.CLIENT_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
            server_id = unpacked_packet[ProtoConsts.SERVER_ID]
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

            # Insert client nonce to RAM DB
            client_ram_template[ProtoConsts.NONCE] = client_nonce

            # Get the client wanted service object from DB
            service_object = self.key_ticket_handler.get_service_object(service_id=server_id,
                                                                        msg_server_list=self.msg_server_list,
                                                                        services_handler=self.services_handler)

            # Pack encrypted key packet
            kdc_aes_key = self.encryptor.generate_bytes_stream(size=ProtoConsts.SIZE_AES_KEY)
            Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=kdc_aes_key)
            packed_encrypted_key_packet = self.key_ticket_handler.pack_encrypted_key_packet(client_ram_template=client_ram_template,
                                                                                            client_nonce=client_nonce,
                                                                                            kdc_aes_key=kdc_aes_key,
                                                                                            encryptor=self.encryptor,
                                                                                            protocol_handler=self.protocol_handler)
            # Pack Ticket packet
            server_aes_key = service_object[AuthConsts.RAM_AES_KEY]
            packed_ticket_packet = self.key_ticket_handler.pack_ticket_packet(client_id=client_id,
                                                                              server_id=server_id,
                                                                              service_aes_key=server_aes_key,
                                                                              kdc_aes_key=kdc_aes_key,
                                                                              encryptor=self.encryptor,
                                                                              protocol_handler=self.protocol_handler)
            # Create packet data frame
            response_data = {
                ProtoConsts.VERSION: ProtoConsts.SERVER_VERSION,
                ProtoConsts.CODE: ProtoConsts.RES_ENCRYPTED_AES_KEY,
                ProtoConsts.PAYLOAD_SIZE: ProtoConsts.SIZE_CLIENT_ID + len(packed_encrypted_key_packet) + len(packed_ticket_packet),
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.ENCRYPTED_KEY: packed_encrypted_key_packet,
                ProtoConsts.TICKET: packed_ticket_packet
            }
            # Pack and send AES key response
            packed_encrypted_key_response = self.protocol_handler.pack_request(code=ProtoConsts.RES_ENCRYPTED_AES_KEY,
                                                                               data=response_data,
                                                                               formatter=server_response.copy())
            server_socket.send_packet(sck=client_socket, packet=packed_encrypted_key_response, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle encrypted key request from {client_socket.getpeername()}.",
                                  exception=e)

