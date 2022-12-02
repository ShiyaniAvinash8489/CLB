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
    System & Device Log 
********************
"""


# Login and Verify OTP
class TestSetUp_LoginAndVerifyOTP(APITestCase):

    def setUp(self):

        self.Login_data = {
            "data": "Z0FBQUFBQmk2bDFKbjRtaUZHMHlWeWlESlllR0xMeWtITDdsRDhaSkZoN1RQeHRMMlRfTnZ0V3ZoR0ZjYUhzZlFiNGxjeGtWWjRrMGg0ZTVVbTNqcjlrbDlUTHNPaUp5bkE9PQ==",
            "phone": "Z0FBQUFBQmk2bDFpbFJWXzZYWW1uMU5TQTZGeFZ4MDZqS1hFdGdZUFltX1dPX3JiSTlsQ3V2U3M3M1NWU2xBMjN3VHZDUkZldmRROWRXR3c1MTAwNmRwTHRtUnBoVGJaUXc9PQ==",


        }

        self.Verify_otp_data = {
            "data": "Z0FBQUFBQmlfSmFTSnBzS3ZfZnhKNUw5YlNkWWlBWFJKN2JSMm5yalpVZV9pMVhxMHAtMi1EdFBUXy01cXdBSlZfNmZKVWY1bTV2VHVUWHhNTE5mRklZWlVjS09adGV1dGRrTzZ5bHRmTWtHSFJxUF9zTWxDWVpiSzc3NllvMmNQMEljcXVhUnFrd0ZaUDRfcjZBaklKN0dlcU9BZHlfSks5Z2xGcVZMSXR5SG9uM1pwN1lEcFVRPQ==",
        }

        return super().setUp()

    def tearDown(self):

        return super().tearDown()
