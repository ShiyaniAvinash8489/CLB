"""
*************************************
        Imported Packages
*************************************
"""

# Status
from rest_framework import status

# AppAdmin - Model
from AppAdmin.models import User

# Reverse URL
from django.urls import reverse

# App End User - SetUp
from AppAdmin.tests.test_setup import (

    # System & Device Log
    TestSetUp_SystemAndDeviceLog,

    # Encrypt & Decrypt
    TestSetUp_EncryptAndDecrypt
)


"""
***************************
    Unit Test Case
***************************
"""


# System & Device Log
class TestLog(TestSetUp_SystemAndDeviceLog):

    """
    System & Device Log
    """

    def test_post_Log(self):
        response_data = self.client.post(reverse("CreateSystemDeviceLog"),
                                         self.log_data, format="json")

        # import pdb
        # pdb.set_trace()
        self.assertEqual(response_data.status_code,
                         status.HTTP_201_CREATED)


# Encrypt & Decrypt
class TestEncryptAndDecrypt(TestSetUp_EncryptAndDecrypt):

    """
    Encrypt_Data
    """

    def test_post_Encrypt_Data(self):
        response_data = self.client.post(reverse("EncrytpData"),
                                         self.Encrypt_data, format="json")

        self.assertEqual(response_data.status_code,
                         status.HTTP_200_OK)

    """
    Encrypt_Data
    """

    def test_post_Encrypt_Data_Error(self):
        response_data = self.client.post(reverse("EncrytpData"),
                                         self.Error_Encrypt_data, format="json")

        self.assertEqual(response_data.status_code,
                         status.HTTP_400_BAD_REQUEST)

    """
    Decrypt_Data
    """

    def test_post_Decrypt_Data(self):
        response_data = self.client.post(reverse("DecryptData"),
                                         self.Decrypt_data, format="json")

        # import pdb
        # pdb.set_trace()
        self.assertEqual(response_data.status_code,
                         status.HTTP_200_OK)

    """
    Decrypt_Data Error
    """

    def test_post_Decrypt_Data_Error(self):
        response_data = self.client.post(reverse("DecryptData"),
                                         self.Error_Decrypt_data, format="json")

        # import pdb
        # pdb.set_trace()
        self.assertEqual(response_data.status_code,
                         status.HTTP_400_BAD_REQUEST)
