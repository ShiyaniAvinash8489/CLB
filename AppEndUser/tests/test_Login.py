# """
# *************************************
#         Imported Packages
# *************************************
# """

# # Status
# from rest_framework import status

# # AppAdmin - Model
# from AppAdmin.models import User

# # Reverse URL
# from django.urls import reverse

# # App End User - SetUp
# from AppEndUser.tests.test_setup import TestSetUp_LoginAndVerifyOTP


# """
# ***************************
#     Unit Test Case
# ***************************
# """


# # Login
# class TestLogin(TestSetUp_LoginAndVerifyOTP):

#     #     """
#     #     Login & SignUp OTP
#     #     """

#     #     def test_post_Login(self):
#     #         response_data = self.client.post(reverse("End_User_Login"),
#     #                                          self.Login_data, format="json")

#     #         # import pdb
#     #         # pdb.set_trace()
#     #         self.assertEqual(response_data.status_code,
#     #                          status.HTTP_201_CREATED)

#     # Error Phone Digit
#     def test_post_Login_Phonedigit(self):

#         self.Login_data = {
#             "data": "Z0FBQUFBQmlfSmxJM3RtZC11Sl9YczNaQ2FleTEtNFAtS3lkdjZpRXE3X1NYQlNuRnB6b2d0R3FkZ2xGNGJXOEJCWFd4elJCUWFIdXdxWEFFTEN5Zk5ONllHWHZrcVpibC12VWtFRFk5REZQT2FEM2NWOXFWS1VGbjYtYXlReEhMN1FTaWRHY2FsYjY=",
#         }

#         response_data = self.client.post(reverse("End_User_Login"),
#                                          self.Login_data, format="json")

#         # import pdb
#         # pdb.set_trace()
#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error phone_length
#     def test_post_Login_phone_length(self):

#         self.Login_data = {
#             "data": "Z0FBQUFBQmlfSmsyd1h1YjVUQ0cxM3l6RVdMdG5VX0pWYTkwSUtCSXh4SnU4WllidGN6UGpzMkZreURtWXU3VnFSQmxJT2tNUjh1ekQ1REtVdlJ5X2ljSG1ldVZYZjJGQUxZdE1FR1pvcERheDlCLW5NdW9CbTVYSFVxYlhpX2xYbDN1YW9FM2VVbU0=",
#         }

#         response_data = self.client.post(reverse("End_User_Login"),
#                                          self.Login_data, format="json")

#         # import pdb
#         # pdb.set_trace()
#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error country_code
#     def test_post_Login_country_code(self):

#         self.Login_data = {
#             "data": "Z0FBQUFBQmlfSmtPbHluQkhOcGp6T0l3NHBmcUYxcjNEeG9jcHppTEZyTE5RbU1ZV19vOE1ybzFNZnM0M3RSNF9BUjZVdEVHOFROQ1pYTFFVb3NZRVNDd2k1VHA5ajMyVHNGeFRObUxPTnZQamxNSjRacDIxY1lOMnN2MWJnbzZndWM1VWY3OC00Zm4===",
#         }

#         response_data = self.client.post(reverse("End_User_Login"),
#                                          self.Login_data, format="json")

#         # import pdb
#         # pdb.set_trace()
#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     """
#     Verify OTP
#     """

#     def test_post_Verify_OTP(self):
#         response_data = self.client.post(reverse("Verify_OTP"),
#                                          self.Verify_otp_data, format="json")

#         # import pdb
#         # pdb.set_trace()
#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error OTP Country Code Invalid
#     def test_post_verify_OTP_country_code_invalid(self):
#         self.Verify_otp_data = {
#             "data": "Z0FBQUFBQmlfSmNjSFB1Z3U2cDFfcjFIdnFsWkNHdkF2MHNYclhIanBPb0tVNWJTa1ZQNHpJdjFEMGpqVjdBZEdGUnluN0d3b1o5YkFYZzViWjVRU2p2NkloMTRSbXhLc3JrV1ZHeDJySEl3OWl2OXBadXpGRGRLRlREa1BpVEE5bDhhUFhGS1dOY2lJWG5QNkhiVkJuS2NNMm40bGhuNlJGSEJTa0hBZTJ4NnNFVHNDVFBFWUNBPQ==",
#         }
#         response_data = self.client.post(reverse("Verify_OTP"),
#                                          self.Verify_otp_data, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error Phone Length
#     def test_post_verify_OTP_phone_length(self):
#         self.Verify_otp_data = {
#             "data": "Z0FBQUFBQmlfSmRIT010LXlWeFlSS2dRSjc3S3pjX0tQRlpsZXAxbmJPVkNIdFNYT2ZrejJUbndMS2FUbGdvVDBQVkozY1V6NXRSbHNudFdwcmxrYUJ4NGM0UFhmbVhVNHhxWG0wYlBIRFhZQkRReFRaNmdFWVoybDhKQmxGRzl4cWd6b0ptaGpYZExfV3lyYlM0UEpCREVNQUJfRWE3YUhnPT0=",
#         }
#         response_data = self.client.post(reverse("Verify_OTP"),
#                                          self.Verify_otp_data, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error PhoneDigit
#     def test_post_verify_Phonedigit(self):
#         self.Verify_otp_data = {
#             "data": "Z0FBQUFBQmlfSmRqektEX1IzaWRsVXQxVUwxSE5fRDNYbE9LMjFsN1pxTDNkLWdaWUoxREczZHpNNm9YbW4xTlVaWUI3YVp3cXljU203V0djaFY4c005akVvVF84YUpHLXROOGM3MzlKSURIVklST3NUN19aay1oODRuNE1MUVIxbkhYSjQ3bDNwT3VjRVV6Y2s4SGZ1VGlOOS1YWlJhS0RkR1p3VVllUFJxUmdzTktTU3lRNG5FPQ==",

#         }
#         response_data = self.client.post(reverse("Verify_OTP"),
#                                          self.Verify_otp_data, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error OTP Digit
#     def test_post_verify_otp_Digit(self):
#         self.Verify_otp_data = {
#             "data": "Z0FBQUFBQmlfSmltVG5ZM2dSd3N3bFVreDlSX0Fud19ULTlIZWdkRTNLdnZwb21JOThGaTBoY2Fyd1dSNWp3MUkxamhMaGc0VlVFc2NJMmo0WXMtdHZYUjZTeHY1TnRmNjVwVGt2NGFydTBPR1FhTXhZYjI3R0pTV3BmcU85cDg5VnNuRkUzVUVuTnhsZFZrRE5LRUN0OWtQMlJ2U09TYTYwQTlLTjkxUGZhODJoeDNmcEZ4ek1FPQ==",
#         }
#         response_data = self.client.post(reverse("Verify_OTP"),
#                                          self.Verify_otp_data, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)
