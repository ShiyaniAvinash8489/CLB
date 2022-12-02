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
from AppAdmin.tests.test_setup import TestSetUp_RegisterAdminUser


"""
***************************
    Unit Test Case
***************************
"""


# # Login
# class TestRegisterUser(TestSetUp_RegisterAdminUser):

#     """
#     Register User
#     """

#     # Positive Test Register
#     def test_post_RegisterUser(self):
#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         # import pdb
#         # pdb.set_trace()
#         self.assertEqual(response_data.status_code,
#                          status.HTTP_201_CREATED)

#     # Error User Term and Condition
#     def test_post_RegisterUser_TNC(self):

#         self.Register_Admin = {
#             "user_tnc": False,
#             "data": "Z0FBQUFBQmlfSDRIWkNpaG5zVVVOY3pnVnNwMFR6WFN2WFhCRktEVVEycjE5R25SNHZUQ2l3ZHQ2Z0o0c2lLZURPN0V2c09YYVRvUXRSa20xLXkyNENKSWVCSmxTWlFtX2tOcDlXdk1VSUpLNEh0OWlwSVFWQjNONE13VlJrMDhySTJyWEJDZ09rZVdETWpjclVMdzU1NF9OX0V1dFZkek9xcVhOMDVpOXZOcHN0UnoxamhOT0dCRTJyX2ZHaWoyTUh0MEpSb2NWZUp0NUo0TEx1YjlrYlktbTMwOGZIOF9FMk1jU1Zqc01EcS1YbGhRNXh4TllZOG40UFJfTEZpZEg3NzctR0N6X1JuSUVNQlpCWkRLQ2p5OWVEVzVwY0t6MnlwT2FHaWxyMGRUOFo2SFFpQ2czRlFXY0wzTm1zVDl5eVFSajYxQkVyYUg===",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User First Name
#     def test_post_RegisterUser_FirstName(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSUR6cm5fLVB5MmY4T1dKOElBT3hnVzFadW9tZUNNMTE4Zkk2OHh0SVZXRFJhWkFLRGJocmd2dW82dFl2eERvVkZjbUR1cWZLQ1hNQ3dOdjZaNDNQamNDakl6M1Bubzh3VUVDR0EyMnNBcGFiTEgyQzRBcDgyVkZrUktOUU9iT0pvRDg4WEVMTmdUVjhiMkRBb1FsbmEzNkpwV0JqdkZEMHduakNZcVprdzR5LUk3aG1SMDg2MWNueDhZSDZLZVIwWFZiekpLTnA4dWtmal9mV09qclNiSGpOR1d3akRQY2Z4YXplcDl3bHBYakwxS19mVEM1Z1RFdTVJM0Q0OEZvb3JGcmRzV1AzTzNPV2ZQWlBVaGpmcFUtLThZM0NKY1lQZl9tVm03NlhDQXN5TzZiT2FZU2NfX3BjSzY0ajVTdVdWOHc=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User Last Name
#     def test_post_RegisterUser_LastName(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSUd0QV95RS11MzR4OURNYTZnRDlySU5YLU9SM3oxdHg2VVhLZ0xuTi1PNTdrNUtzd2RCRkxWWC01ZGtOVmJ1a3p0SUozTk1PQ1hJN0s5cTd0NFRQVkI2aldNWjlqWFVyTWVocU1wUm1MMTJwOU9XY0xZbVRtS2IyXzFEbnFZN1pwV3U5elVoTVQtNVpqUHJpcUQ2VTRzRHlIbjQ4MlhGWFhyQlJ6b0tpczBnMlduYkFsaDlfR1VXbVowZ3RmLXRROWIyMjFBWDVwRVd3R1NYUUY2bDI3TXR1Z2dTREdxZlBEMWhiOXpIMlV6bkJJQTVLSGF6bUprVFJfTkUzRDFicDJWekloUzE5RkpHQklqNTl4YWQzRG05d0xZTEFfejE2aVBvcHBRQTkzX2hIZkxzLWdSN0dEZHlwMmpQaVR5WE04X2Y=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User UserName
#     def test_post_RegisterUser_UserName(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSU1VX2VkcXdqR2pXbkFjWXpIMnRGVXFBYkVWazlBa2VtWWdUNmNqTkhLdE0wVnMxQ21iYVRoZlhuOEE3RzA2V2szMnlHc2IwWFVBOTZORmU1Y1d4Z0NpeU5zVzd3RFNBQ0dSTzRXSDlialhycWY3bGc0ajZPTVh1QUk4SjY2X3RjWVhaaTJKSmUzUkZ3MWxtZ0VlRkpyN0ExTEh5ZHdGUEk4VFJ2Qm9fLVp1dm9IaFlSYTNhdktVMEJsM05CMzdhcDl3VFhFdEQzSWpMSTNEdTlHTUxXbnBySGMxSnpuOXhUOU1wMk4yellRYXhZWmFxOHRuX3hQVlFSd2FBbGFaYXZXSXRQWmtmQVhqMW5ieDI2dHljc0M5ZldPVW9SemhlYWZJa3ZHd0YtTEZ4N0tBVEN0RVYyeXltSlRSRzIwbXJyaXM=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User Email
#     def test_post_RegisterUser_Email(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSU5RNk5xY1hIdm9ZWEt6RF9Xd0h1ajR4YksyM2FhQlFNYkhUQTNHQk9hLTJndjF2SmlVbFNPZm5fMzhoMmhMbjFwM3RablkwWTA3YXNIbEVheUJ2UHJYZm9ycWpJWUE1cUFucDFIb2hkaXNVYUttWHZReE5BQTl2Y0syRHIwNkplaGZSZEJUczFiSmc0RDRHcEhxUVZuUlNkSW8yWjhXOFBTV3VHVVNTc3hfaHhJbHRyMDdyZUYyci1mODBNU081RXJtdE12RHl2aVFnekdQZWRyTlVnY2x3djNIMXM2b2pNNldzckJqM216Zmg0WjZwVndQTUdvSW5qMTEtdTBMNy02VDJIblhBV1VKX1gya2gxTnRGRmswcW5IdDlPbGFtdXZodEZmcmRJdGlmYTJrMXM5VTYyeXVmMjE4S2Fwc2h2akw=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User Mobile - Digit
#     def test_post_RegisterUser_Mobile_Digit(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSU5fS3lLS190LWlraGp3VkVuME5OOE56NzB3VmlHX0lsTHVrWnBoaVkwbEw5RE5JU2VDa3JiR29qdGdrQ1BUWXhWdkgwUG4zV2VmNDlXV0U5dF9OUGtwNG1NYll0eXA2OGVKQkRTYlVxekdCSW1PTHNrQzh2YktkVEJZUG1SYjJBMWdsODdHZ2FudVRHbEI4ODZ2U2t2Tm03UTFyWmZ4UG1lTURXMlJGLXRTZG5iWEZ4cFJSVTlDeVhKZnhFcUd0c21USWdfX19qdm95T2NxWUJnOWRBandxS1U4cmNQQVdveGk4RkdwZU1fdWtGc2hxUG12MlRLV2l4a2hCZGZvand0VHJjODdYMi1vYm5UY1VQMlpYVFd1ek5LeFFzQkV4X0Y2MkNMeDZZTFhQWWE4M0lPa1hfNHNTcXloNGMxeGk5a3g=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User Mobile - Length
#     def test_post_RegisterUser_Mobile_Length(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSVBrTk5acHdOdTBvYk1aNFZ0OUpmRmJJbFg3aDVTeVRrYWFjT0diV3pvTTRfOU9sbFBUVVVwbkktVlVJNWdURl9LNkEtNkxRVHJtMUNQenRiYzdaU2JtdzBQYkJSX3pWU09vTENJZ0xCT0gxUlJKcmVmeGYzY3dQRk9pTEZxTTVjb2xldUd1QkVsMi13SnM5WFJMMTdGZXhTbXNuck4zMTR4b3RUYzBCX0RTQkpFQk5mT181THNQc2dBdFdSaHBtYTBNVktWcENKTU9VYVNVbFh3dzdTTFp0WWpKa0IyMkFFcTFPUlJ4V2pJR2JWYVRHZWc5Q3Y2eXd3OGJXcTUzck5lTWRvOXFfYm1BYWhrZ2E3cUR3VlZMdHdweVhZMFlBUlJlcDNfRFBFWUJjb0hsVUMwWkc1LW1JT0VTSVBJWnRiZ2w=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User Country Code
#     def test_post_RegisterUser_Country_code(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSVE0S3VGOVc5ZFpmX3pPeGVQOWstczgtaUZ5d2ZXbEhodi1DU0psV3BUX0VHdl9maEZteFlrWEFNRXdGTFJsRFZXUEZfN1RJN0R0RjNSUzN3NElnMENfMm5vam9tUFJzMDJfZk8td09pM3Z4T0pWa1otVmZra285NjM4RERKSDZaYUFZNEtWTUJDajVwSkh0SHZzT2MxMHd2MnlMcXMwTl9VNjZuWXBGWUNjYVN3RTNRVlFpbGUyY2JYSlJSS0JQY1R6YnZqSlZKaTE4b3RFNy0yUENkNUtKdTN2MVZLb1BKZlpJVUxKX2ZNZzFQQjU0SXJpODZ6eEoyMHkxcGJ4aHVpOWVVc2laMUl0eXFBZmllQnE4UG5yOGpBUnNhUnlVWEJKdmwwVm9ydWlEMS01S2pRZVMwYXFDNDA4bkpqaHJ6RFE=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)

#     # Error User Password
#     def test_post_RegisterUser_Password(self):

#         self.Register_Admin = {
#             "user_tnc": True,
#             "data": "Z0FBQUFBQmlfSVJsdHluUUJPQ2RuZ2M3VmxJZE1ZY1QzUEtRRDN5VWIxLWdGejlqdkRsOW80MDFBdFJtay1NM3dFOFFIcHdmcmxFVjYzOXNiVS0tUU9ZUEg4RHY1a25mRDB3bGpmejUxSHk1WWp0ajBucDRJRDcwMmFwMHBPYVhNVUVaSkZTT1FEbFBlUnRxcDEwNGZpbkUxZ090LTdwRzZZTXN1N2VtZ1hWN1FOWHI3bnVYdzVsUnotZTZTdHFsVG5WdlBrd3l0cWxmUi0wOG9IbVNlM1ZrUllMeHJST1RFQkxlcE9PLTlnN3JUQ3FjSXdDXzhkY1JXN3BzdkZGczFINExKbXBEandZZnJRUGpQeTdCeC0zTXRVVU1zbkFuRGZXaWxGLUV5STNnM0t5ak9senVrZlJuck5aWnpqenV1MFA4QkRsTTVWVE4=",
#         }

#         response_data = self.client.post(reverse("RegisterUser"),
#                                          self.Register_Admin, format="json")

#         self.assertEqual(response_data.status_code,
#                          status.HTTP_400_BAD_REQUEST)
