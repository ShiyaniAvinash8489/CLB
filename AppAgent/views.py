"""
*********
Rest Framework
*********
"""

# Permission
from ast import Delete
from shutil import ExecError
from rest_framework import permissions
from AppAgent.models import Agent_Verify_Email_Mobile
from AppEndUser.CustomPermission import OnlyEndUser
from AppAdmin.CustomPermission import AllowSuperAdminUser, IsOwnerAndIsSuperAdmin

# Response
from rest_framework.response import Response

# Class - Generic
from rest_framework.generics import GenericAPIView, UpdateAPIView, ListAPIView
from rest_framework.views import APIView

# Parser & Status
from rest_framework.parsers import MultiPartParser
from rest_framework import status

# Language Translation
from django.utils.translation import gettext_lazy as _

# Serializers
from rest_framework.serializers import Serializer

# Error handling
from rest_framework.exceptions import NotFound

# Swagger
from drf_yasg.utils import swagger_auto_schema

# Json Web Token
import jwt
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.tokens import RefreshToken
from AppAdmin.DecodeJWT import DecodeJWT

# Email for verification
from AppAdmin.EmailConfig import SendEmail
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.template.loader import get_template

# Forget Password
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import (
    smart_str,
    force_str,
    smart_bytes,
    DjangoUnicodeDecodeError,
)

# Twilio Settings
from twilio.rest import Client
from django.conf import settings
from twilio.base import exceptions
from twilio.base.exceptions import TwilioRestException, TwilioException

# Error - Logging
from AppAdmin.Error_Log import Error_Log

# JSON Renderer For Encrypt Decrypt
from rest_framework.renderers import JSONRenderer

# Encrypt Decrypt data
from AppAdmin.EncryptDecrypt import encrypt_data, decrypt_data, Json_decrypt_data

# Upload CSV File
import csv
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage

# Q Object
from django.db.models import Q
from django.db.models import F, Sum, Avg

# Other
from django.http import HttpResponsePermanentRedirect
from django.http import Http404

# Data Time
import datetime

# Json
import json

# Regex
import re

# Custom Pagination
from AppAdmin.MyPagination import Pagination_Page_50

# For Redis
from django.core.cache.backends.base import DEFAULT_TIMEOUT
from django.core.cache import cache

# Indian Post API for Getting details of Pincode
from AppAdmin.PincodeAPI import Indian_Post_Pincode

# AuthToken
from AppAdmin.AuthToken import DecodeToken


# OTP Generate & Send Email
from AppAgent.otp_generate import SendEmailForOTP


# Models - Admin
from AppAdmin.models import (
    # User Models
    User,
)


# End User Serializers
from AppEndUser.serializers import (

    # Verify OTP Login
    VerifyOTP_serializers,

)


# Admin User Serializers
from AppAdmin.serializers import (
    ChangePassword_Serializer,
)

# Agent Serializer.
from AppAgent.serializers import (

    # Verify Email & Phone
    VerifyEmailPhone_Serializers,
    Verify_Email_OTP_serializers,

    # Agent Register
    RegisterAgentUser_Serializers,
    Agent_Address_Serializers,
    Agent_Bank_Details_Serializers,
    Agent_KYC_Serializers,

    # Agent Login
    Agent_Login_Serializers,

    # Agent Update Profile
    Agent_Update_Profile_serializers,






)


"""
**************************************************************************
                            Create Your Business Logic here
**************************************************************************
"""

"""
********************
    Twilio Settings
********************
"""

# Twilio Settings
client = Client(settings.TWILIO_SID, settings.TWILIO_AUTH_TOKEN)
verify = client.verify.services(settings.TWILIO_SERVICE_ID)


"""
****************************************************************************************************************************************************************
                                                                 Agent
****************************************************************************************************************************************************************
"""


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [settings.APP_SCHEME, 'http', 'https']


"""
****************************************************************************************************************************************************************
                                                                 Verify Email & phone
****************************************************************************************************************************************************************
"""

"""
**********
    Send Email OTP and Phone OTP
**********
"""


class Agent_Send_EmailPhone_OTP_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = VerifyEmailPhone_Serializers

    @swagger_auto_schema(tags=["Agent Email OTP & Phone OTP"], operation_description=("Payload", '{"email": "string","country_code": "string","phone": "String"}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            Agent_Verify_Email_Mobile.objects.filter(
                exp_datetime__lt=datetime.datetime.now()).delete()
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                """===================== Send OTP  ====================="""

                verify.verifications.create(to=str(response_data["country_code"]
                                                   )+str(response_data["phone"]), channel='sms')

                """===================== Email ====================="""

                SendEmailForOTP(
                    email=response_data["email"], id=user_data["id"])

                print("\n\n\n\n")
                return Response({
                    "response_code": 200,
                    "response_message": _("OTP has been  send Email for Verifing on your registerd Email"),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_200_OK)
            else:
                if serializer.errors.get('email_exists'):
                    return Response({"response_code": 400, "response_message": _("Email already is existed.")}, status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('phone_exists'):
                    return Response({"response_code": 400, "response_message": _("Phone Number already is existed.")}, status=status.HTTP_400_BAD_REQUEST)
                # Validation
                elif serializer.errors.get('email_validation'):
                    return Response({"response_code": 400, "response_message": _("Please, Enter the correct E-Mail.")}, status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Phonedigit'):
                    return Response({"response_code": 400, "response_message": _("Phone number must be numeric")}, status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Phonelength'):
                    return Response({"response_code": 400, "response_message": _('Phone must be bewtween 8  to 12 Characters')}, status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except TwilioException as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e.args[2])}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
**********
    Verify Mobile OTP
**********
"""


class Agent_Verify_Mobile_OTP_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = VerifyOTP_serializers

    @swagger_auto_schema(tags=["Agent Email OTP & Phone OTP"], operation_description=('Payload:', '{"country_code":"String","phone" : "String","otpCode": "String"} '),)
    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=False):
            decrypt_datas = Json_decrypt_data(request.data["data"])

            try:
                result = verify.verification_checks.create(
                    to=str(decrypt_datas["country_code"]+decrypt_datas["phone"]), code=decrypt_datas["otpCode"])

                if result.status == "approved":
                    Agent_Verify_Email_Mobile.objects.filter(
                        phone=decrypt_datas["phone"]).update(is_verify_phone=True)

                    return Response({
                        "response_code": 200,
                        "response_message": "Phone has been verified",
                    }, status=status.HTTP_200_OK)

                elif result.status == "pending":
                    return Response({
                        "response_code": 400,
                        "response_message": _("Please enter correct OTP, you have entered the incorrect one")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif result.status == "expired":
                    return Response({
                        "response_code": 400,
                        "response_message": _("Your OTP is Expired. Please Resend OTP.")},
                        status=status.HTTP_400_BAD_REQUEST)

            except TwilioRestException as e:
                return Response({
                    "response_code": 400,
                    "response_message": _("Invalid OTP, Please Resend OTP ")},
                    status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                Error_Log(e)
                return Response({
                    "response_code": 400,
                    "response_message": _(e)},
                    status=status.HTTP_400_BAD_REQUEST)
            return Response(serializer.data, status=status.HTTP_200_OK)

        else:
            # Phone
            if serializer.errors.get("country_code_invalid"):
                return Response({
                    "response_code": 400,
                    "response_message": _("Country code must be start with '+', and Numeric")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("phone_length"):
                return Response({
                    "response_code": 400,
                    "response_message": _("Please enter phone number between 10 to 20 length'")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("Phonedigit"):
                return Response({
                    "response_code": 400,
                    "response_message": _("Phone number must be numeric")},
                    status=status.HTTP_400_BAD_REQUEST)

            # OTP
            elif serializer.errors.get("otp_Digit"):
                return Response({
                    "response_code": 400,
                    "response_message": _("OTP must be Only Numberic")},
                    status=status.HTTP_400_BAD_REQUEST)
        return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


"""
**********
    Verify Email OTP
**********
"""


class Agent_Verify_Email_OTP_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Verify_Email_OTP_serializers

    @swagger_auto_schema(tags=["Agent Email OTP & Phone OTP"], operation_description=("Payload: ", '{"email": "String","otpCode": "String"}'),)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            decrypt_datas = Json_decrypt_data(request.data["data"])

            email = decrypt_datas["email"]
            otp = decrypt_datas["otpCode"]

            try:
                Check_OTP = Agent_Verify_Email_Mobile.objects.filter(Q(email=email) & Q(
                    exp_datetime__gt=datetime.datetime.now()) & Q(is_verify=False))

                if Agent_Verify_Email_Mobile.objects.filter(Q(email=email) & Q(otp=otp) & Q(exp_datetime__gt=datetime.datetime.now()) & Q(is_verify=False)):
                    Agent_Verify_Email_Mobile.objects.filter(Q(email=email) &
                                                             Q(otp=otp)).update(is_verify=True, is_verify_email=True)

                    return Response({
                        "responseCode": 200,
                        "responseMessage": _("Successfully, Verified Email OTP"),
                    }, status=status.HTTP_200_OK)

                elif Agent_Verify_Email_Mobile.objects.filter(Q(email=email) & Q(otp=otp) & Q(exp_datetime__gt=datetime.datetime.now()) & Q(is_verify=True)):
                    return Response({
                        "responseCode": 400,
                        "responseMessage": _("Email OTP Already is verified."),
                    }, status=status.HTTP_400_BAD_REQUEST)

                elif Agent_Verify_Email_Mobile.objects.filter(Q(email=email) & Q(otp=otp) & Q(exp_datetime__lt=datetime.datetime.now()) & Q(is_verify=False)):

                    return Response({
                        "responseCode": 400,
                        "responseMessage": _("Email OTP is expired."),
                    }, status=status.HTTP_400_BAD_REQUEST)

                elif Check_OTP:

                    for i in Check_OTP:
                        if i.otp == otp:
                            Agent_Verify_Email_Mobile.objects.filter(Q(email=email) & Q(
                                otp=otp)).update(is_verify=True, is_verify_email=True)
                        else:
                            return Response({
                                "responseCode": 400,
                                "responseMessage": _("Invalid OTP"),
                            }, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                Error_Log(e)
                return Response({
                    "response_code": 400,
                    "response_message": _(e)},
                    status=status.HTTP_400_BAD_REQUEST)
        else:

            return Response({'responseCode': status.HTTP_400_BAD_REQUEST, "responseMessage": serializer.errors})


"""
****************************************************************************************************************************************************************
                                                                 Register Agent User
****************************************************************************************************************************************************************
"""


"""
************
    Create Agent User
************
"""


class Register_Agent_User_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = RegisterAgentUser_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Register Agent"], operation_description=("Payload: ", '{"first_name": "string","middle_name": "string","last_name": "string","username": "string","country_code": "string","phone": "string","email": "string","password": "string",}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = serializer.data["id"]

                return Response({
                    "response_code": 201,
                    "response_message": _("Agent User is Successfully registered "),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('Password_Length'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Passwords must be bewtween 6  to 25 Characters.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('user_tnc'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Please agree to all the term and condition")},
                        status=status.HTTP_400_BAD_REQUEST)
                # Exists
                elif serializer.errors.get('username_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Username already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('email_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Email already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('phone_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone Number already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)
                # Validation
                elif serializer.errors.get('email_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Please, Enter the correct E-Mail.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Phonedigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Phonelength'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Phone must be bewtween 8  to 12 Characters')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('FirstName_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('First Name or Last Name or Agent must be alphbet.')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Not_Verify_Email'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Register Email is not virefy. ')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Not_Verify_phone'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Register Phone is not virefy. ')},
                        status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        # except TwilioException as e:
        #     Error_Log(e)
        #     return Response({"code": 400, "message": _(e.args[2])}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
************
   Agent Address
************
"""


class Create_Agent_Address_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Agent_Address_Serializers

    @swagger_auto_schema(tags=["Register Agent"], operation_description=("Payload: ", '{"user_id": intger,"address_line_1": "String","address_line_2": "String","landmarks": "String","city": "String","state": "String","pincode": "String","country": "String",}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = serializer.data["id"]

                return Response({
                    "response_code": 201,
                    "response_message": _("Successfully, Agent Address has been registered."),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('user_id'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("You should enter user address.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('address_line_1'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("You should enter Address.")},
                        status=status.HTTP_400_BAD_REQUEST)
                # Exists
                elif serializer.errors.get('city'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("City must be enterd.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('pincode'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("pincode must be enterd.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('User_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exists.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
************
   Agent bank Details
************
"""


class Create_Agent_Bank_Details_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Agent_Bank_Details_Serializers
    # parser_classes = [MultiPartParser, ]

    @swagger_auto_schema(tags=["Register Agent"], operation_description=('in data {"user_id": integer, "bank_name": "string","branch_name": "String","IFSC_code": "String","account_number": "string",}, cancel_cheque = Base64Image'))
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = serializer.data["id"]
                response_data["cancel_cheque"] = serializer.data["cancel_cheque"]

                return Response({
                    "response_code": 201,
                    "response_message": _("Successfully, Agent Bank Details has been registered."),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('User_id'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User Id must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('User_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exists.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('bank_empty'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Bank Name must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('branch_empty'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Branch Name must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('ifsc_empty'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("IFSC Code must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('ifsc_alphnum'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("IFSC Code must be AlphaNumeric.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('account_empty'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Account Number must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('account_alphnum'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Account Number must be AlphaNumeric.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
************
   Agent KYC Details
************
"""


class Create_Agent_KYC_Details_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Agent_KYC_Serializers
    # parser_classes = [MultiPartParser, ]

    @swagger_auto_schema(tags=["Register Agent"], operation_description=('in data {"user_id": integer, "bank_name": "string","branch_name": "String","IFSC_code": "String","account_number": "string",}, cancel_cheque = Base64Image'))
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, many=True)
            if serializer.is_valid(raise_exception=False):
                serializer.save()

                return Response({
                    "response_code": 201,
                    "response_message": _("Successfully, Kyc Is uploaded "),
                    "response_data": serializer.data},
                    status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('User_id'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User Id must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
************
   Agent Login
************
"""


class AgentLogin_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Agent_Login_Serializers
    # renderer_classes = (UserRenderer)

    @ swagger_auto_schema(tags=["Agent Login"], operation_description=("payload", '{"email":"string","password" : "string"}'),)
    def post(self, request):
        serializer = self.serializer_class(data=request.data,
                                           context={"request": request})

        if serializer.is_valid(raise_exception=False):
            Json_data = Json_decrypt_data(request.data["data"])
            user = User.objects.get(email=Json_data["email"]).id
            try:
                User_Details = User.objects.get(id=user)

                Response_Data = encrypt_data({
                    "user_id": user,
                    "token": {'refresh': User_Details.tokens()['refresh'],
                              'access': User_Details.tokens()['access']}
                })

                return Response({
                    "response_code": 200,
                    "response_message": _("Login Successfully."),
                    "response_data": {
                        "user_id": user,
                        "token": {'refresh': User_Details.tokens()['refresh'],
                                  'access': User_Details.tokens()['access']}
                    },
                }, status=status.HTTP_200_OK)

            except TwilioException as e:
                Error_Log(e)
                return Response({"response_code": 400, "response_message": _(e.args[2])}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                Error_Log(e)
                return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)
        else:
            if serializer.errors.get("Invalid_Credentials"):
                return Response({
                    "response_code": 401,
                    "response_message": _("Invalid credentials, try again")},
                    status=status.HTTP_401_UNAUTHORIZED)

            elif serializer.errors.get("Isverify"):
                return Response({
                    "response_code": 400,
                    "response_message": _("Your account is not verified by admin.")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("NonAgent_User"):
                return Response({
                    "response_code": 401,
                    "response_message": _("Only, Agent will allow to login.")},
                    status=status.HTTP_401_UNAUTHORIZED)

            elif serializer.errors.get("Active_User"):
                return Response({
                    "response_code": 400,
                    "response_message": _("Please, Contact to Admin. ")},
                    status=status.HTTP_400_BAD_REQUEST)

            # elif serializer.errors.get("BankDetails"):
            #     return Response({
            #         "response_code": 400,
            #         "response_message": _("Your Bank account is not verified by admin ")},
            #         status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("KYC_Details"):
                return Response({
                    "response_code": 400,
                    "response_message": _("Your KYC is not verified by admin")},
                    status=status.HTTP_400_BAD_REQUEST)

        return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


"""
************
   Agent Change Password 
************
"""


class Agent_Change_Password_view(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerAndIsSuperAdmin]

    serializer_class = ChangePassword_Serializer

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    @ swagger_auto_schema(tags=["Agent Update Profile"], operation_description=("Payload: ", '{"old_password" : "String","new_password" : "String"}'),)
    def put(self, request, *args, **kwargs):
        try:
            self.object = self.get_object()

            # Decode Token
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            serializer = self.get_serializer(data=request.data)

            # Decrypt Data
            Json_data = Json_decrypt_data(request.data["data"])

            if serializer.is_valid():
                if not self.object.check_password(Json_data["old_password"]):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Old Password does not matched."), },
                        status=status.HTTP_400_BAD_REQUEST)

                self.object.set_password(Json_data["new_password"])
                self.object.save()

                User.objects.filter(id=UserID).update(
                    updated_by=str(UserID))

                return Response({
                    "response_code": 200,
                    "response_message": _("Password has been updated successfully"), },
                    status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
************
   Agent Update Profile 
************
"""


class Agent_Update_Profile_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerAndIsSuperAdmin]
    # permission_classes = [AllowSuperAdminUser]

    serializer_class = Agent_Update_Profile_serializers
    # renderer_classes = (UserRenderer)

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Agent Update Profile"], operation_description=("Payload:", '{"first_name": "String","middle_name": "String","last_name": "String","username":"String","country_code": "String","phone": "String","email": "String"}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)
            # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                User.objects.filter(id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                # Encrypt
                response_data_encrypt = encrypt_data(response_data)

                return Response({
                    "response_code": 200,
                    "response_message": _("Agent User profile has been updated."),
                    "response_data": response_data_encrypt, },
                    status=status.HTTP_200_OK)

            else:

                if serializer.errors.get('username_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Username already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('email_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Email already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('phone_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone Number already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)
                # Validation
                elif serializer.errors.get('email_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Please, Enter the correct E-Mail.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Phonedigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Phonelength'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Phone must be bewtween 8  to 12 Characters')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('FirstName_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('First Name or Last Name or Agent must be alphbet.')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Not_Verify_Email'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Register Email is not virefy. ')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Not_Verify_phone'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Register Phone is not virefy. ')},
                        status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except TwilioException as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e.args[2])}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)
