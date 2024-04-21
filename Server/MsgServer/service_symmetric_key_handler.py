from Utils.utils import is_expired, insert_data_to_json_db
from Utils.logger import Logger, CustomFilter
from Utils.validator import Validator, ValConsts
from Utils.encryptor import Encryptor
from Utils.custom_exception_handler import CustomException, get_calling_method_name
from Socket.custom_socket import CustomSocket, socket
from Protocol_Handler.protocol_constants import ProtoConsts
from Protocol_Handler.protocol_handler import ProtocolHandler
from Protocol_Handler.protocol_templates import packet_no_payload, code_to_payload_template, server_request, server_response
from Server.MsgServer.msg_server_constants import MsgConsts


class SymmetricKeyHandler:
    """Handles Msg Server Symmetric Key request logic."""

    def __init__(self, debug_mode: bool) -> None:
        self.debug_mode = debug_mode
        self.logger = Logger(logger_name=self.__class__.__name__, debug_mode=debug_mode)

    def __process_authenticator_packet(self, authenticator: bytes, kdc_aes_key: bytes,
                                       encryptor: Encryptor, protocol_handler: ProtocolHandler) -> dict:
        """Returns the decrypted unpacked Authenticator data."""
        try:
            # Unpack Authenticator packet
            authenticator_data = protocol_handler.unpack_request(received_packet=authenticator,
                                                                 formatter=code_to_payload_template[
                                                                                ProtoConsts.PKT_AUTHENTICATOR].copy())
            # Unpack Authenticator data
            authenticator_iv, version, client_id, server_id, creation_time = authenticator_data

            # Decrypt and validate data
            decrypted_version = int(encryptor.decrypt(encrypted_value=version,
                                                      decryption_key=kdc_aes_key,
                                                      iv=authenticator_iv).decode())
            Validator.validate_injection(data_type=ValConsts.FMT_VERSION, value_to_validate=decrypted_version)
            decrypted_client_id = encryptor.decrypt(encrypted_value=client_id,
                                                    decryption_key=kdc_aes_key,
                                                    iv=authenticator_iv)
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=client_id)
            decrypted_server_id = encryptor.decrypt(encrypted_value=server_id,
                                                    decryption_key=kdc_aes_key,
                                                    iv=authenticator_iv)
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)
            decrypted_creation_time = encryptor.decrypt(encrypted_value=creation_time,
                                                        decryption_key=kdc_aes_key,
                                                        iv=authenticator_iv).decode()
            Validator.validate_injection(data_type=ValConsts.FMT_ID, value_to_validate=server_id)

            # Create data frame
            processes_authenticator_data = {
                ProtoConsts.VERSION: decrypted_version,
                ProtoConsts.CLIENT_ID: decrypted_client_id,
                ProtoConsts.SERVER_ID: decrypted_server_id,
                ProtoConsts.CREATION_TIME: decrypted_creation_time
            }
            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Decrypted authenticator packet --> {processes_authenticator_data}"
            self.logger.logger.debug(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(msg)

            # Return the processed data
            return processes_authenticator_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to process authenticator packet.", exception=e)

    def __process_ticket_packet(self, ticket: bytes, service_aes_key: bytes, ram_template: dict,
                                encryptor: Encryptor, protocol_handler: ProtocolHandler) -> dict:
        """Returns the decrypted unpacked Ticket data."""
        try:
            # Unpack Ticket packet
            ticket_data = protocol_handler.unpack_request(received_packet=ticket,
                                                          formatter=code_to_payload_template[
                                                                                ProtoConsts.PKT_TICKET].copy())
            # Unpack Ticket data
            version, client_id, server_id, creation_time, ticket_iv, ticket_aes_key, expiration_time = ticket_data
            ram_template[MsgConsts.RAM_TICKET_IV] = Validator.validate_injection(data_type=ValConsts.FMT_IV,
                                                                                 value_to_validate=ticket_iv)

            # Decrypt and validate data
            decrypted_creation_time = encryptor.decrypt(encrypted_value=creation_time,
                                                        decryption_key=service_aes_key,
                                                        iv=ticket_iv).decode()
            Validator.validate_injection(data_type=ValConsts.FMT_CREATION_TIME, value_to_validate=decrypted_creation_time)
            decrypted_aes_key = encryptor.decrypt(encrypted_value=ticket_aes_key,
                                                  decryption_key=service_aes_key,
                                                  iv=ticket_iv)
            Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=decrypted_aes_key)
            ram_template[MsgConsts.RAM_KDC_AES_KEY] = decrypted_aes_key
            decrypted_expiration_time = encryptor.decrypt(encrypted_value=expiration_time,
                                                          decryption_key=service_aes_key,
                                                          iv=ticket_iv).decode()
            Validator.validate_injection(data_type=ValConsts.FMT_CREATION_TIME, value_to_validate=decrypted_creation_time)

            # Create data frame
            processes_ticket_data = {
                ProtoConsts.VERSION: version,
                ProtoConsts.CLIENT_ID: client_id,
                ProtoConsts.SERVER_ID: server_id,
                ProtoConsts.CREATION_TIME: decrypted_creation_time,
                ProtoConsts.AES_KEY: decrypted_aes_key,
                ProtoConsts.EXPIRATION_TIME: decrypted_expiration_time
            }
            # Log
            CustomFilter.filter_name = get_calling_method_name()
            msg = f"Decrypted ticket packet --> {processes_ticket_data}"
            self.logger.logger.debug(msg=msg)

            # For dev mode
            if self.debug_mode:
                print(msg)

            # Return the processed data
            return processes_ticket_data

        except Exception as e:
            raise CustomException(error_msg=f"Unable to process ticket packet.", exception=e)

    def __validate_symmetric_key_data(self, authenticator_data: dict, ticket_data: dict) -> bool:
        """Validates Client received unpacked and decrypted Symmetric Key data."""
        try:
            if ticket_data[ProtoConsts.SERVER_ID] != authenticator_data[ProtoConsts.SERVER_ID]:
                return False

            if ticket_data[ProtoConsts.CLIENT_ID] != authenticator_data[ProtoConsts.CLIENT_ID]:
                return False

            if is_expired(ticket_data[ProtoConsts.EXPIRATION_TIME]):
                return False

            self.logger.logger.info(msg=f"Symmetric key data validated successfully.")
            return True

        except Exception as e:
            raise CustomException(error_msg=f"Unable to validate symmetric key request data.", exception=e)

    def handle_symmetric_key_request(self, sck: CustomSocket, client_socket: socket, ram_template: dict,
                                     encryptor: Encryptor, protocol_handler: ProtocolHandler) -> bool:
        try:
            # Receive request
            symmetric_key_request = sck.receive_packet(sck=client_socket, logger=self.logger)
            request_code, unpacked_symmetric_key_request = protocol_handler.unpack_request(received_packet=symmetric_key_request,
                                                                                           formatter=server_request.copy(),
                                                                                           code=ProtoConsts.REQ_MSG_SERVER_AES_KEY,
                                                                                           deserialize=True)
            # Fetch and validate service AES key
            aes_key = ram_template[MsgConsts.RAM_SERVICE_AES_KEY]
            Validator.validate_injection(data_type=ValConsts.FMT_AES_KEY, value_to_validate=aes_key)

            # Process Ticket packet
            ticket = unpacked_symmetric_key_request[ProtoConsts.TICKET]
            ticket_data = self.__process_ticket_packet(ticket=ticket,
                                                       service_aes_key=aes_key,
                                                       ram_template=ram_template,
                                                       encryptor=encryptor,
                                                       protocol_handler=protocol_handler)
            # Process Authenticator packet
            authenticator = unpacked_symmetric_key_request[ProtoConsts.AUTHENTICATOR]
            authenticator_data = self.__process_authenticator_packet(authenticator=authenticator,
                                                                     kdc_aes_key=ticket_data[ProtoConsts.AES_KEY],
                                                                     encryptor=encryptor,
                                                                     protocol_handler=protocol_handler)

            # Verify data
            if self.__validate_symmetric_key_data(authenticator_data=authenticator_data, ticket_data=ticket_data):

                # Insert unpacked values to JSON DB
                insert_data_to_json_db(file_path=MsgConsts.SERVICE_POOL_FILE_PATH,
                                       data=ram_template,
                                       pivot_key=MsgConsts.RAM_SERVICE_ID_HEX,
                                       pivot_value=ram_template[MsgConsts.RAM_SERVICE_ID_HEX])
                # Return success
                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_AES_KEY_ACK
                packed_symmetric_key_ack = protocol_handler.pack_request(code=ProtoConsts.RES_AES_KEY_ACK,
                                                                         data=packet_no_payload,
                                                                         formatter=server_response.copy())
                sck.send_packet(sck=client_socket, packet=packed_symmetric_key_ack, logger=self.logger)
                return True

            # Return general error
            else:
                packet_no_payload[ProtoConsts.CODE] = ProtoConsts.RES_GENERAL_ERROR
                packed_general_error = protocol_handler.pack_request(code=ProtoConsts.RES_GENERAL_ERROR,
                                                                     data=packet_no_payload,
                                                                     formatter=server_response.copy())
                sck.send_packet(sck=client_socket, packet=packed_general_error, logger=self.logger)

        except Exception as e:
            raise CustomException(error_msg=f"Unable to handle symmetric key request.", exception=e)