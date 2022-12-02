"""
*************************************
        Imported Packages 
*************************************
"""


# Test - DRF
from rest_framework.test import APITestCase, APIClient


"""
**************************************************************************
                            Test Setup
**************************************************************************
"""

"""
********************
    Register Admin User
********************
"""


# Register Admin User
class TestSetUp_RegisterAdminUser(APITestCase):

    def setUp(self):

        self.Register_Admin = {
            "user_tnc": True,
            "data": "Z0FBQUFBQmlfSDRIWkNpaG5zVVVOY3pnVnNwMFR6WFN2WFhCRktEVVEycjE5R25SNHZUQ2l3ZHQ2Z0o0c2lLZURPN0V2c09YYVRvUXRSa20xLXkyNENKSWVCSmxTWlFtX2tOcDlXdk1VSUpLNEh0OWlwSVFWQjNONE13VlJrMDhySTJyWEJDZ09rZVdETWpjclVMdzU1NF9OX0V1dFZkek9xcVhOMDVpOXZOcHN0UnoxamhOT0dCRTJyX2ZHaWoyTUh0MEpSb2NWZUp0NUo0TEx1YjlrYlktbTMwOGZIOF9FMk1jU1Zqc01EcS1YbGhRNXh4TllZOG40UFJfTEZpZEg3NzctR0N6X1JuSUVNQlpCWkRLQ2p5OWVEVzVwY0t6MnlwT2FHaWxyMGRUOFo2SFFpQ2czRlFXY0wzTm1zVDl5eVFSajYxQkVyYUg===",
        }

        return super().setUp()

    def tearDown(self):

        return super().tearDown()


"""
********************
    System & Device Log 
********************
"""


# System & Device Log
class TestSetUp_SystemAndDeviceLog(APITestCase):

    def setUp(self):

        self.log_data = {
            "os_type": "Window",
            "os_version": "10.5",
            "device": "Mobile",
            "device_type": "IOS",
            "browser": "Safari",
            "brower_version": "15.5"

        }

        return super().setUp()

    def tearDown(self):

        return super().tearDown()


# Encrypt & Decrypt
class TestSetUp_EncryptAndDecrypt(APITestCase):

    def setUp(self):

        self.Encrypt_data = {
            "encrypt_Data": "+91",
        }

        self.Decrypt_data = {
            "decrypt_Data": "Z0FBQUFBQmk2bUdGSkRQS2JQRzNKamQ0Sk42TVdyUGZKYVJtRW9QOHNReUVpSEZtQXhrWUtwb242NFZVN3pBclhNb2h0S3RlelJzc0lxMVRLSVJRcXVtSk1JM2lkYzdRS2c9PQ==",
        }

        self.Error_Encrypt_data = {
            "encrypt_Data": " "
        }

        self.Error_Decrypt_data = {
            "decrypt_Data": " ",
        }

        return super().setUp()

    def tearDown(self):

        return super().tearDown()
