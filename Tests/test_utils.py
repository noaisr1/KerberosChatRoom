from unittest import TestCase, main as unittest_main
from os import path as os_path, remove
from sys import path as sys_path
sys_path.append('..')
from Utils import utils
from Server.AuthServer.auth_server_constants import AuthConsts
from Client.client_constants import CConsts, me_info_default_data
from Server.MsgServer.msg_server_constants import MsgConsts


def create_test_file(file_name: str, file_data: dict) -> None:
    with open(file_name, 'w') as f:
        for key, value in file_data.items():
            f.write(f"{value}\n")


class TestUtils(TestCase):

    def setUp(self) -> None:
        self.port_info_file = MsgConsts.PORT_FILE_PATH
        self.me_info_file = CConsts.CLIENT_FILE_NAME
        self.msg_info_file = MsgConsts.MSG_FILE_NAME
        self.clients_file = AuthConsts.CLIENTS_FILE_NAME
        create_test_file(file_name=self.port_info_file, file_data={"port": 8000})
        create_test_file(file_name=self.me_info_file, file_data=me_info_default_data)
        create_test_file(file_name=self.msg_info_file, file_data={"port": 1234, "name": "Printer 20"})
        create_test_file(file_name=self.clients_file, file_data={"Line1": "ID: Name: PasswordHash: LastSeen"})

    def tearDown(self) -> None:
        if os_path.exists(self.port_info_file):
            remove(self.port_info_file)
        if os_path.exists(self.me_info_file):
            remove(self.me_info_file)
        if os_path.exists(self.msg_info_file):
            remove(self.msg_info_file)
        if os_path.exists(self.clients_file):
            remove(self.clients_file)

    def test_search_value_in_file(self) -> None:
        result = utils.search_value_in_txt_file("Name", self.clients_file)
        self.assertEqual(result, True)


if __name__ == '__main__':
    unittest_main(verbosity=2)