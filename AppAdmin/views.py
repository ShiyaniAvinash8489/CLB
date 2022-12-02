"""
*********
Rest Framework
*********
"""

# Permission
from tkinter.tix import Tree
from turtle import Turtle
from rest_framework import permissions
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

# Search & Filter
from rest_framework.filters import SearchFilter
import django_filters


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
from AppAdmin.EncryptDecrypt import encrypt_data, decrypt_data, Json_decrypt_data, OrderDict_to_json

# Upload CSV File
import csv
from django.core.files.base import ContentFile
from django.core.files.storage import FileSystemStorage

# Q Object
from django.db.models import Q
from django.db.models import F, Sum, Avg, Count

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

# Other Function Generate
from AppAdmin.FunctionGen import sendPush

# Models - Admin
from AppAdmin.models import (
    # User Models
    Banner,
    CLB_Review,
    Offer_discount,
    User,

    # System And Device Log - Models
    SystemAndDeviceLog,

    # Pincode - Model
    Pincode_DB,

    # Booking Slot
    BookingSlot,

    # Courier
    CourierCompany,

    # Courier_Company_Review
    Courier_Company_Review,

    # Price
    PriceForCustomer,
    Our_Price,

    # FAQ
    FAQ_Cateogry,
    FAQ,

    # Contact us
    ContactUs,

    # Ticket SUpport
    Issue_Category,
    Support_Ticket,

    # Notification
    Notification,
)


# Agent Models
from AppAgent.models import (
    Agent_Bank_Details,
    Agent_KYC,
    Agent_Address,
)

# Admin Serializer.
from AppAdmin.serializers import (
    # Register Admin User
    RegisterAdminUser_Serializers,

    # Update Admin Profile
    UpdateAdminUser_Serializers,

    # Change Password
    ChangePassword_Serializer,

    # Verify Email
    EmailVerification_Serializers,

    # Super Admin - Login
    SuperAdminLogin_Serializers,
    AdminLogin_Serializers,

    # Forget Password
    ResetPasswordEmailRequest_Serializer,
    SetNewPassword_Serializer,
    SetNewPassword_Serializer,

    # Get User Details
    GetUserDetails_serializers,
    Search_User_Serializres,

    # System Serializer
    SystemAndDeviceLog_Serializers,

    # Encrypt  And Decrypt
    Encrypt_Serailizers,
    Decrypt_Serailizers,

    # Import CSV File
    ImportCSVFileSerializers,

    # Booking Slot
    Admin_BookSlot_Serializers,

    # Pincode
    Pincode_serializers,

    # Agent Verify KYC & Bank
    Agent_Verify_Bank_byAdmin_Serializers,
    Agent_Verify_KYC_byAdmin_Serializers,

    # CLB Review
    CLB_Review_Serializers,
    Courier_Company_Review_Serializers,

    # Courier
    Courier_Company_Serializers,
    Courier_Copmany_List_Delete_serializers,


    # PRice
    CreatePriceForCustomer_Serializers,
    ListPriceForCustomer_Serializers,
    CreatePriceForUS_Serializers,
    ListPriceForUs_Serializers,



    # FAQ
    faq_category_encrypt_serializers,
    faq_category_serializers,
    faq_ecrypt_serializers,
    faq_serializers,

    # Contact us
    CountactUs_Serializers,
    CountactUs_Update_Serializers,


    # Issue / Ticket / Support
    issue_Category_encrypt_serializers,
    issue_Category_serializers,
    admin_SupportTicket_Serializers,
    SupportTicket_Admin_Encrypt_Serializres,


    # Notification
    Notification_Serializers,

    # Banner
    banner_serializers,
    Banner_Encrypt_Serializers,


    # Offer Discount
    Offer_discount_encrypt_serializers,
    Offer_discount_serializers,



)


# End User Serializers
from AppEndUser.serializers import (

    # Verify OTP Login
    VerifyOTP_serializers,
)

# Agent Serializers
from AppAgent.serializers import (
    Agent_KYC_for_admin_Serializers,
    Agent_Bank_Details_for_admin_Serializers,
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
                                                                 Admin
****************************************************************************************************************************************************************
"""


class CustomRedirect(HttpResponsePermanentRedirect):
    allowed_schemes = [settings.APP_SCHEME, 'http', 'https']


"""
********************
    Register & Update Admin
********************
"""


class RegisterAdminuser_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowSuperAdminUser]

    serializer_class = RegisterAdminUser_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Register Admin"], operation_description=("Payload:", '{"first_name": "String","last_name": "String","username":"String","country_code": "String","phone": "String","email": "String","password": "String"}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]
                response_data["user_tnc"] = user_data["user_tnc"]

                """===================== Email ====================="""
                # Send Email for verifing
                user = User.objects.get(id=user_data["id"])

                SendEmail.send_email({
                    "email_body": get_template('welcome.html').render({
                        "Name": f"{user.first_name} {user.last_name}",
                        'verfiy_link': (
                            "http://" +
                            get_current_site(request).domain +
                            reverse("Email-Verify") + "?token="
                            + str(RefreshToken.for_user(user).access_token)
                        )}),
                    "to_email": user.email,
                    "email_subject": "verify your Accountaa",
                })

                return Response({
                    "response_code": 201,
                    "response_message": _("Admin User is Successfully registered. send Email for Verifing on your registerd Email"),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
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
                        "response_message": _('First Name and Last Name must be alphbet.')},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except TwilioException as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e.args[2])}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


class UpdateAdminUserProfile_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerAndIsSuperAdmin]
    # permission_classes = [AllowSuperAdminUser]

    serializer_class = UpdateAdminUser_Serializers
    # renderer_classes = (UserRenderer)

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Register Admin"], operation_description=("Payload:", '{"first_name": "String","last_name": "String","username":"String","country_code": "String","phone": "String","email": "String"}'),)
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
                    "response_message": _("Admin User profile has been updated."),
                    "response_data": response_data_encrypt, },
                    status=status.HTTP_200_OK)

            else:

                # Exists
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
                        "response_message": _('First Name must be alphbet.')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Last_Name_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Last Name must be alphbet.')},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except TwilioException as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e.args[2])}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


class ChangeAdminPassword_view(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsOwnerAndIsSuperAdmin]

    serializer_class = ChangePassword_Serializer

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    @ swagger_auto_schema(tags=["Register Admin"], operation_description=("Payload: ", '{"old_password" : "String","new_password" : "String"}'),)
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
********************
    Verify Email
********************
"""


class VerifyEmail_Views(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = EmailVerification_Serializers

    @ swagger_auto_schema(tags=["Register Admin"], operation_description="Verify Email ",)
    def get(self, request):
        token = request.GET.get("token")  # Get Token

        try:
            # Decode Token
            payload = jwt.decode(token, settings.SECRET_KEY,
                                 algorithms="HS256")
            user = User.objects.get(id=payload["user_id"])

            if user.is_verify:
                return Response({
                    "response_code": 200,
                    "response_message": _("Already, Your Account have been verified")},
                    status=status.HTTP_200_OK)

            elif not user.is_verify:
                user.is_verify = True
                user.save()

                return Response({
                    "response_code": 200,
                    "response_message": _("Your Account is verified.")},
                    status=status.HTTP_200_OK)

        except jwt.ExpiredSignatureError as ESE:
            Error_Log(ESE)
            return Response({"response_code": 400, "response_message": _("Your link is expired.")}, status=status.HTTP_400_BAD_REQUEST)

        except jwt.exceptions.DecodeError as EDecode:
            Error_Log(EDecode)
            return Response({"response_code": 400, "response_message": _("Your link is Invalid.")}, status=status.HTTP_400_BAD_REQUEST)
        return Response({"error": _("Invalid token")}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Super Admin Login
********************
"""


class SuperAdminLogin_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = SuperAdminLogin_Serializers
    # renderer_classes = (UserRenderer)

    @ swagger_auto_schema(tags=["Admin Login"], operation_description=("payload", '{"email":"String","password" : "String"}'),)
    def post(self, request):
        serializer = self.serializer_class(data=request.data,
                                           context={"request": request})

        if serializer.is_valid(raise_exception=False):

            Json_data = Json_decrypt_data(request.data["data"])
            user = User.objects.get(email=Json_data["email"])
            country_code, phone = user.country_code, user.phone
            mobile = str(country_code+phone)

            if User.objects.filter(phone=phone):
                try:
                    # Check In Memory
                    if cache.get("mobile"):
                        return Response({
                            "response_code": 400,
                            "response_message": f'You can try to send OTP after {cache.ttl("mobile")} seconds.'},
                            status=status.HTTP_400_BAD_REQUEST)
                    else:

                        # Send OTP
                        verify.verifications.create(to=mobile, channel='sms')

                        # Set Key & Value Pair in Memory for 2 Min
                        cache.set("mobile", mobile, 60 * 2)

                        return Response({
                            "response_code": 200,
                            "response_message": _("The Login OTP has been sent to registered phone number. "),
                            "response_data": encrypt_data({"country_code": country_code, "phone": phone})},
                            status=status.HTTP_200_OK)

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
                    "response_message": _("Admin User is not Active")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("Normal_User"):
                return Response({
                    "response_code": 401,
                    "response_message": _("Super Admin will allow to login.")},
                    status=status.HTTP_401_UNAUTHORIZED)

        return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Admin Login
********************
"""


class AdminLogin_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = AdminLogin_Serializers
    # renderer_classes = (UserRenderer)

    @ swagger_auto_schema(tags=["Admin Login"], operation_description=("payload", '{"email":"string","password" : "string"}'),)
    def post(self, request):
        serializer = self.serializer_class(data=request.data,
                                           context={"request": request})

        if serializer.is_valid(raise_exception=False):
            Json_data = Json_decrypt_data(request.data["data"])
            user = User.objects.get(email=Json_data["email"])

            country_code, phone = user.country_code, user.phone
            mobile = str(country_code+phone)

            if User.objects.filter(phone=phone):
                try:
                    # Check In Memory
                    if cache.get("mobile"):
                        return Response({
                            "response_code": 400,
                            "response_message": f'You can try to send OTP after {cache.ttl("mobile")} seconds.'},
                            status=status.HTTP_400_BAD_REQUEST)
                    else:

                        # Send OTP
                        verify.verifications.create(to=mobile, channel='sms')

                        # Set Key & Value Pair in Memory for 2 Min
                        cache.set("mobile", mobile, 60 * 2)

                        return Response({
                            "response_code": 200,
                            "response_message": _("The Login OTP has been sent to registered phone number. "),
                            "response_data": encrypt_data({"country_code": country_code, "phone": phone})},
                            status=status.HTTP_200_OK)

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
                    "response_message": _("Admin User is not Active")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get("Normal_User"):
                return Response({
                    "response_code": 401,
                    "response_message": _("Super Admin will allow to login.")},
                    status=status.HTTP_401_UNAUTHORIZED)

        return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Admin - Verify Login :
********************
"""


class AdminVerifyLoginOTP_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = VerifyOTP_serializers
    # parser_classes = [MultiPartParser, ]

    @ swagger_auto_schema(tags=["Admin Login"], operation_description=('Payload:', '{"country_code":"String","phone" : "String","otpCode": "String"} '),)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=False):
            decrypt_datas = Json_decrypt_data(request.data["data"])

            # Send Mobile Otp
            country_code = decrypt_datas["country_code"]
            phone = decrypt_datas["phone"]
            otpCode = decrypt_datas["otpCode"]

            try:
                result = verify.verification_checks.create(
                    to=str(country_code+phone), code=otpCode)

                if result.status == "approved":
                    user1 = User.objects.get(phone=phone).id

                    user = User.objects.get(id=user1)

                    token = {'refresh': user.tokens()['refresh'],
                             'access': user.tokens()['access']}

                    Response_Data = encrypt_data({
                        "user_id": user1,
                        "user_type": "Admin",
                        "country_code": country_code,
                        "phone": phone,
                        "token": {'refresh': user.tokens()['refresh'],
                                  'access': user.tokens()['access']}
                    })

                    return Response({
                        "response_code": 200,
                        "response_message": _("Login Successfully."),
                        "response_data": Response_Data,
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
                return Response({"response_code": 400, "response_message": _("Invalid OTP, Please Resend OTP ")}, status=status.HTTP_400_BAD_REQUEST)
            except Exception as e:
                Error_Log(e)
                return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)
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
********************
    Forget Password
********************
"""


# Request Forget Password
class RequestPasswordResetEmail_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = ResetPasswordEmailRequest_Serializer

    @ swagger_auto_schema(tags=["Forget Password - Admin "], operation_description=("payload: ", '{"email":"string","redirect_url":"string}'),)
    def post(self, request):
        try:
            decrypt_datas = Json_decrypt_data(request.data["data"])

            # Send Mobile Otp
            email = decrypt_datas["email"]
            redirect_url = decrypt_datas["redirect_url"]

            if not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', email):
                return Response({
                    "response_code": 400,
                    "response_message": _("Please enter correct email.")},
                    status=status.HTTP_400_BAD_REQUEST)

            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)
                if (user.is_staff != True and user.is_superuser != True):
                    return Response({
                        "response_code": 401,
                        "response_message": _("You can not Send email for changing password of Admin User.")},
                        status=status.HTTP_401_UNAUTHORIZED)

                SendEmail.send_email({
                    "email_body": get_template('forgetPassword.html').render({
                        'verfiy_link': 'http://'+get_current_site(request=request).domain + reverse(
                            'passwordResetConfirm', kwargs={
                                'uidb64': urlsafe_base64_encode(smart_bytes(user.id)),
                                'token': PasswordResetTokenGenerator().make_token(user)
                            })+"?redirect_url="+redirect_url
                    }),
                    "to_email": user.email,
                    "email_subject": "Reset your password",
                })

            return Response({
                            "response_code": 200,
                            "response_message": _("Email has been sent to register E-Mail.")},
                            status=status.HTTP_200_OK)
        except Exception as e:
            Error_Log(e)
            return Response({
                "response_code": 400,
                "response_message": _(e)},
                status=status.HTTP_400_BAD_REQUEST)


# Set Token For Forgetting Password
class PasswordTokenCheckAPI_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    @ swagger_auto_schema(tags=["Forget Password - Admin "], operation_description="This API don't need to access this api is for check Token.",)
    def get(self, request, uidb64, token):

        redirect_url = request.GET.get('redirect_url')

        try:
            id = smart_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(id=id)
            # ----------------------------------------------------------------------------------------

            if not PasswordResetTokenGenerator().check_token(user, token):
                if len(redirect_url) > 3:
                    return CustomRedirect(redirect_url+'?token_valid=False')
                else:
                    return CustomRedirect((settings.FRONTEND_URL, '')+'?token_valid=False')

            if redirect_url and len(redirect_url) > 3:
                return CustomRedirect(redirect_url+'?token_valid=True&message=Credentials Valid&uidb64='+uidb64+'&token='+token)
            else:
                return CustomRedirect(settings.FRONTEND_URL+'?token_valid=False')

        except DjangoUnicodeDecodeError as identifier:
            if not PasswordResetTokenGenerator().check_token(user):
                return Response(
                    {"error": _("Token is not valid, please request a new one")},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


class SetNewPasswordAPI_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = SetNewPassword_Serializer

    @ swagger_auto_schema(tags=["Forget Password - Admin "], operation_description=("payload:", '{"password":"String","token": "String","uidb64": "String"}'),)
    def patch(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid(raise_exception=False):
            return Response({
                "response_code": 200,
                "response_message": _("Your Password have been reseted.")},
                status=status.HTTP_200_OK)
        else:
            if serializer.errors.get('Password_Length'):
                return Response({
                    "response_code": 400,
                    "response_message": _("Passwords must be bewtween 6  to 25 Characters.")},
                    status=status.HTTP_400_BAD_REQUEST)
            elif serializer.errors.get('Reset_Link'):
                return Response({
                    "response_code": 400,
                    "response_message": _("The Reset link is invalid.")},
                    status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Get Admin User Details
********************
"""


class Admin_User_Details_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowSuperAdminUser]

    serializer_class = GetUserDetails_serializers

    @ swagger_auto_schema(tags=["Get User Details"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        AdminUser = User.objects.filter(Q(is_active=True) & Q(
            is_staff=True) & Q(is_superuser=False) & Q(user_type="Admin"))

        if AdminUser:
            serializer = self.serializer_class(
                AdminUser, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Soft Detelte Admin user
********************
"""


class softDelete_AdminUser_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowSuperAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = GetUserDetails_serializers

    queryset = User.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Soft Delete User"], operation_description="Get Admin User Details",)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        user_id_for_del = self.get_object(pk)

        if not user_id_for_del.is_superuser:
            if user_id_for_del.is_active == True and user_id_for_del.is_verify == True:

                user_id_for_del.is_active = False
                user_id_for_del.is_verify = False

                user_id_for_del.save()

                User.objects.filter(id=pk).update(
                    updated_by=str(UserID))

                return Response(
                    {"responseCode": 200,
                     'responseMessage': _("Successfully Deleted")},
                    status=status.HTTP_200_OK)

            return Response(
                {"responseCode": 400,
                 'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"responseCode": 400,
             'responseMessage':  _("You cannot delete ADMIN User.")},
            status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Search Admin User 
********************
"""


class Search_AdminUser_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    queryset = User.objects.filter(Q(is_active=True) & Q(user_type="Admin"))
    serializer_class = Search_User_Serializres
    filter_backends = [SearchFilter]
    search_fields = ["first_name", "middle_name", "last_name",
                     "username", "phone", "email", "user_type"]


"""
****************************************************************************************************************************************************************
                                                                 Other
****************************************************************************************************************************************************************
"""

"""
********************
    System & Device Log
********************
"""


class SystemAndDeviceLog_Create_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = SystemAndDeviceLog_Serializers

    @ swagger_auto_schema(tags=["Log Details"], operation_description="This API for getting System log and Store in Database.",)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=False):
            try:
                serializer.save()
                return Response({
                    "code": 201,
                    "message": _("Log has been stored."),
                    "data": encrypt_data(OrderDict_to_json(serializer.data)), },
                    status=status.HTTP_201_CREATED)
            except Exception as e:
                Error_Log(e)
                return Response({"code": 400, "message": _("Invalid OTP, Please Resend OTP ")}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({"code": 400, "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Encrypt  & Decrypt
********************
"""


class Encrypt_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Encrypt_Serailizers

    @ swagger_auto_schema(tags=["Encrypt & Decrypt"], operation_description="This API is for decrypt to encrypt.")
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=False):
            try:
                Encrypt_Data = request.data["encrypt_Data"]

                return Response({
                    "code": 200,
                    "message": _("Encrypt - Data "),
                    "data": encrypt_data(Encrypt_Data),
                }, status=status.HTTP_200_OK)

            except Exception as e:

                return Response({
                    "code": 400,
                    "message": _(e)},
                    status=status.HTTP_400_BAD_REQUEST)

        else:

            return Response({"code": 400, "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


class Decrypt_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Decrypt_Serailizers

    @ swagger_auto_schema(tags=["Encrypt & Decrypt"], operation_description="This API is for encrypt to decrypt.")
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=False):

            try:
                Decrypt_Data = request.data["decrypt_Data"]
                return Response({
                    "code": 200,
                    "message": _("Decrypt - Data "),
                    "data": decrypt_data(Decrypt_Data),
                }, status=status.HTTP_200_OK)

            except Exception as e:

                return Response({
                    "code": 400,
                    "message": _(e)},
                    status=status.HTTP_400_BAD_REQUEST)

        else:

            return Response({"code": 400, "message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


"""
******************************************************************************************************************
                                      Import Excel File & Export PDF
******************************************************************************************************************
"""


"""
*********
    Pincode - Upload CSV
*********
"""


fs = FileSystemStorage(location='Upload_CSV_File/')


class ImportCSVFileViews_Pincode(GenericAPIView):
    """
    A simple ViewSet for viewing and editing Product.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = ImportCSVFileSerializers
    parser_classes = [MultiPartParser]

    @ swagger_auto_schema(tags=["Upload CSV File"], operation_description="This API is for Uploading Pincode CSV File. ")
    def post(self, request, *args, **kwargs):
        try:
            # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # Pincode_DB.objects.all().delete()
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid(raise_exception=False):
                file = serializer.validated_data['file']
                if ".csv" == str(file)[-4:]:

                    reader = csv.reader(open(
                        fs.path(fs.save("_Pincode.csv", ContentFile(file.read()))), errors="ignore"))

                    next(reader)

                    product_list = []
                    for id_, row in enumerate(reader):
                        (Courier_Company_Name, Pincode, City, State,
                         Zone, CLBPickUP, Delivery) = row

                        cc_name = CourierCompany.objects.get(
                            name=Courier_Company_Name)

                        if cc_name.is_active == True:

                            if CLBPickUP == "TRUE":
                                CLBPickUP = True
                            elif CLBPickUP == "FALSE":
                                CLBPickUP = False

                            if Delivery == "TRUE":
                                Delivery = True
                            elif Delivery == "FALSE":
                                Delivery = False

                            if not Pincode_DB.objects.filter(Q(CC_Pin_id=cc_name) & Q(pincode=Pincode) & Q(City=City) & Q(State=State)).exists():
                                # For Saving Data
                                product_list.append(Pincode_DB(CC_Pin_id=cc_name,
                                                               pincode=Pincode, City=City, State=State, Country="India", is_clb_pickup=CLBPickUP,  is_delivery=Delivery, created_by=UserID))
                            continue
                        else:
                            return Response({"response_code": 400, 'response_message': _(f"{cc_name.name} is not activated")}, status=status.HTTP_400_BAD_REQUEST)

                    if len(product_list) > 0:
                        Pincode_DB.objects.bulk_create(product_list)
                        return Response({"response_code": 201, 'response_message': _(f"{len(product_list)} Record added successfully")}, status=status.HTTP_201_CREATED)
                    else:
                        return Response({"response_code": 201, 'response_message': _("Record(s) already exists")}, status=status.HTTP_201_CREATED)

                else:
                    return Response({"response_code": 406, 'response_message': _("File does not supported.")}, status=status.HTTP_406_NOT_ACCEPTABLE)

        except ValueError as ve:
            Error_Log(ve)
            return Response({"response_code": 400, 'response_message': "Value Error: {0}".format(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except csv.Error as ce:
            Error_Log(ce)
            return Response({"response_code": 400, 'response_message': "CSV Error: {0}".format(ce)}, status=status.HTTP_400_BAD_REQUEST)
        except TypeError as te:
            Error_Log(te)
            return Response({"response_code": 400, 'response_message': "Type Error: {0}".format(te)}, status=status.HTTP_400_BAD_REQUEST)
        except CourierCompany.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Courier Company name does Not Exsits"}, code=status.HTTP_404_NOT_FOUND)


"""
*********
    Price For Customer- Upload CSV
*********
"""


class ImportCSVFileViews_Price(GenericAPIView):
    """
    A simple ViewSet for viewing and editing Product.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = ImportCSVFileSerializers
    parser_classes = [MultiPartParser]

    @ swagger_auto_schema(tags=["Upload CSV File"], operation_description="This API is for Uploading Pincode CSV File. ")
    def post(self, request, *args, **kwargs):
        try:
            # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # PriceForCustomer.objects.all().delete()
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid(raise_exception=False):
                file = serializer.validated_data['file']
                if ".csv" == str(file)[-4:]:

                    reader = csv.reader(open(
                        fs.path(fs.save("_Price.csv", ContentFile(file.read()))), errors="ignore"))

                    next(reader)

                    product_list = []
                    for id_, row in enumerate(reader):
                        (Courier_Company_Name, Service_Type, Shipment_Type, Travel_By,
                         Weight_From, Weight_To, Price_Local, Price_State, Price_Rest_Of_India, ) = row

                        cc_name = CourierCompany.objects.get(
                            name=Courier_Company_Name)

                        if cc_name.is_active == True:

                            if not PriceForCustomer.objects.filter(
                                Q(CC_Price_id=cc_name)
                                & Q(ServiceType=Service_Type)
                                & Q(ShipmentType=Shipment_Type)
                                & Q(TravelBy=Travel_By)
                                & Q(Weight_From=Weight_From)
                                & Q(Weight_To=Weight_To)
                            ).exists():
                                # For Saving Data
                                product_list.append(PriceForCustomer(CC_Price_id=cc_name,
                                                                     ServiceType=Service_Type, ShipmentType=Shipment_Type, TravelBy=Travel_By, Weight_From=Weight_From, Weight_To=Weight_To,  Local=Price_Local, State=Price_State, RestOfIndia=Price_Rest_Of_India, created_by=UserID))
                            continue
                        else:
                            return Response({"response_code": 400, 'response_message': _(f"{cc_name.name} is not activated")}, status=status.HTTP_400_BAD_REQUEST)

                    if len(product_list) > 0:
                        PriceForCustomer.objects.bulk_create(product_list)
                        return Response({"response_code": 201, 'response_message': _(f"{len(product_list)} Record added successfully")}, status=status.HTTP_201_CREATED)
                    else:
                        return Response({"response_code": 201, 'response_message': _("Record(s) already exists")}, status=status.HTTP_201_CREATED)

                else:
                    return Response({"response_code": 406, 'response_message': _("File does not supported.")}, status=status.HTTP_406_NOT_ACCEPTABLE)

        except ValueError as ve:
            Error_Log(ve)
            return Response({"response_code": 400, 'response_message': "Value Error: {0}".format(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except csv.Error as ce:
            Error_Log(ce)
            return Response({"response_code": 400, 'response_message': "CSV Error: {0}".format(ce)}, status=status.HTTP_400_BAD_REQUEST)
        except TypeError as te:
            Error_Log(te)
            return Response({"response_code": 400, 'response_message': "Type Error: {0}".format(te)}, status=status.HTTP_400_BAD_REQUEST)
        except CourierCompany.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Courier Company name does Not Exsits"}, code=status.HTTP_404_NOT_FOUND)


"""
*********
    Price For Customer- Upload CSV
*********
"""


class ImportCSVFileViews_PriceForUs(GenericAPIView):
    """
    A simple ViewSet for viewing and editing Product.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = ImportCSVFileSerializers
    parser_classes = [MultiPartParser]

    @ swagger_auto_schema(tags=["Upload CSV File"], operation_description="This API is for Uploading Pincode CSV File. ")
    def post(self, request, *args, **kwargs):
        try:
            # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # PriceForCustomer.objects.all().delete()
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid(raise_exception=False):
                file = serializer.validated_data['file']
                if ".csv" == str(file)[-4:]:

                    reader = csv.reader(open(
                        fs.path(fs.save("_PriceOur.csv", ContentFile(file.read()))), errors="ignore"))

                    next(reader)

                    product_list = []
                    for id_, row in enumerate(reader):
                        (Courier_Company_Name, Service_Type, Shipment_Type, Travel_By,
                         Weight_From, Weight_To, Price_Local, Price_State, Price_Rest_Of_India, ) = row

                        cc_name = CourierCompany.objects.get(
                            name=Courier_Company_Name)

                        if cc_name.is_active == True:

                            if not Our_Price.objects.filter(
                                Q(CC_OurPrice_id=cc_name)
                                & Q(ServiceType=Service_Type)
                                & Q(ShipmentType=Shipment_Type)
                                & Q(TravelBy=Travel_By)
                                & Q(Weight_From=Weight_From)
                                & Q(Weight_To=Weight_To)
                            ).exists():
                                # For Saving Data
                                product_list.append(Our_Price(CC_OurPrice_id=cc_name,
                                                              ServiceType=Service_Type, ShipmentType=Shipment_Type, TravelBy=Travel_By, Weight_From=Weight_From, Weight_To=Weight_To,  Local=Price_Local, State=Price_State, RestOfIndia=Price_Rest_Of_India, created_by=UserID))
                            continue
                        else:
                            return Response({"response_code": 400, 'response_message': _(f"{cc_name.name} is not activated")}, status=status.HTTP_400_BAD_REQUEST)

                    if len(product_list) > 0:
                        Our_Price.objects.bulk_create(product_list)
                        return Response({"response_code": 201, 'response_message': _(f"{len(product_list)} Record added successfully")}, status=status.HTTP_201_CREATED)
                    else:
                        return Response({"response_code": 201, 'response_message': _("Record(s) already exists")}, status=status.HTTP_201_CREATED)

                else:
                    return Response({"response_code": 406, 'response_message': _("File does not supported.")}, status=status.HTTP_406_NOT_ACCEPTABLE)

        except ValueError as ve:
            Error_Log(ve)
            return Response({"response_code": 400, 'response_message': "Value Error: {0}".format(ve)}, status=status.HTTP_400_BAD_REQUEST)
        except csv.Error as ce:
            Error_Log(ce)
            return Response({"response_code": 400, 'response_message': "CSV Error: {0}".format(ce)}, status=status.HTTP_400_BAD_REQUEST)
        except TypeError as te:
            Error_Log(te)
            return Response({"response_code": 400, 'response_message': "Type Error: {0}".format(te)}, status=status.HTTP_400_BAD_REQUEST)
        except CourierCompany.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Courier Company name does Not Exsits"}, code=status.HTTP_404_NOT_FOUND)


"""
******************************************************************************************************************
                                        Booking Slot
******************************************************************************************************************
"""

"""
***************
    Get All Booking Slot
***************
"""


class Get_All_Booking_Slot_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = Admin_BookSlot_Serializers

    @ swagger_auto_schema(tags=["Booking Slot"], operation_description="Super admin & Admin will create Booking SLot, using by this api",)
    def get(self, request, format=None):
        BookingSlot_Data = BookingSlot.objects.filter(
            is_active=True).order_by("id")

        serializer = self.serializer_class(
            BookingSlot_Data, many=True, context={"request": request})

        return Response(
            {"code": 200,
             'message': _("Success"),
             'data': encrypt_data(OrderDict_to_json(serializer.data))},
            status=status.HTTP_200_OK)


"""
***************
    Create Booking Slot
***************
"""


class Create_Booking_Slot_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    serializer_class = Admin_BookSlot_Serializers

    @ swagger_auto_schema(tags=["Booking Slot"], operation_description="Super admin & Admin will create Booking SLot, using by this api",)
    def post(self, request, *args, **kwargs):
        try:
            # """===================== Decode JWT  ====================="""
            # token = self.request.headers["Authorization"]
            # UserID = DecodeJWT(token)

            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()

                """===================== Create By & Update On ====================="""
                # BookingSlot.objects.filter(
                #     id=serializer.data['id']).update(created_by=str(UserID))

                return Response({
                    "response_code": 201,
                    "response_message": _("Booking Slot has been created."),
                    "response_data": encrypt_data(serializer.data)},
                    # "response_data": serializer.data},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get("Invalid_Time"):
                    return Response({
                        "response_code": 400,
                        "response_message": _("End time is less than Start Time")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get("invalid_Allow_time"):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Allow time is less than start or greater than end time. ")},
                        status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***************
    Update Booking Slot
***************
"""


class Update_Booking_Slot_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    serializer_class = Admin_BookSlot_Serializers
    # parser_classes = [MultiPartParser]

    def get_object(self, pk):
        try:
            return BookingSlot.objects.get(pk=pk)
        except BookingSlot.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Booking Slot"], operation_description="Super admin & Admin will create Booking SLot, using by this api",)
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
                BookingSlot.objects.filter(
                    id=serializer.data['id']).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                return Response({
                    "response_code": 200,
                    "response_message": _("Booking Slot has been updated."),
                    "response_data": encrypt_data(OrderDict_to_json(serializer.data)), },
                    status=status.HTTP_200_OK)
            else:
                if serializer.errors.get("Invalid_Time"):
                    return Response({
                        "response_code": 400,
                        "response_message": _("End time is less than Start Time")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get("invalid_Allow_time"):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Allow time is less than start or greater than end time. ")},
                        status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***************
    Delete Booking Slot
***************
"""


class Hard_Delete_Booking_Slot_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    serializer_class = Admin_BookSlot_Serializers

    def get_object(self, pk):
        try:
            return BookingSlot.objects.get(pk=pk)
        except BookingSlot.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Booking Slot"], operation_description="Super admin & Admin will delete Booking SLot, using by this api",)
    def delete(self, request, pk, format=None):
        Mark_ID = self.get_object(pk)
        Mark_ID.delete()
        return Response(
            {"responseCode": 200,
             'responseMessage': _("Successfully Deleted")},
            status=status.HTTP_200_OK)


"""
****************************************************************************************************************************************************************
                                                                 Pincode
****************************************************************************************************************************************************************
"""


"""
***************
    Get All Pincode
***************
"""


class Get_All_Pincode_Views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    queryset = Pincode_DB.objects.filter(is_active=True).order_by("id")
    serializer_class = Pincode_serializers
    pagination_class = Pagination_Page_50


"""
***************
    Get All Pincode
***************
"""


class Get_All__Delete_Pincode_Views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    queryset = Pincode_DB.objects.filter(is_active=False).order_by("id")
    serializer_class = Pincode_serializers
    pagination_class = Pagination_Page_50


"""
***************
    Create Pincode
***************
"""


class Create_Pincode_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = Pincode_serializers

    @swagger_auto_schema(tags=["Pincode"], operation_description="Super admin & Admin will create Booking SLot, using by this api",)
    def post(self, request, *args, **kwargs):
        try:
            # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            serializer = self.serializer_class(
                data=request.data, context={"request": request}, many=True)
            if serializer.is_valid(raise_exception=False):
                serializer.save()

                """===================== Create By & Update On ====================="""
                Pincode_DB.objects.filter(
                    id=serializer.data['id']).update(created_by=str(UserID))

                return Response({
                    "response_code": 201,
                    "response_message": _("Pincode has been created."),
                    "response_data": encrypt_data(OrderDict_to_json(serializer.data))},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get("Pincode_Exists"):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Already, Pincode is exists.")},
                        status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***************
    Update Pincode
***************
"""


class Update_Pincode_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    serializer_class = Pincode_serializers
    # parser_classes = [MultiPartParser]

    def get_object(self, pk):
        try:
            return Pincode_DB.objects.get(pk=pk)
        except Pincode_DB.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Pincode"], operation_description="Update Pincode",)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)
            """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                Pincode_DB.objects.filter(
                    id=serializer.data['id']).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                return Response({
                    "response_code": 200,
                    "response_message": _("Pincode has been updated."),
                    "response_data": encrypt_data(OrderDict_to_json(serializer.data)), },
                    status=status.HTTP_200_OK)
            else:
                if serializer.errors.get("Pincode_Exists"):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Already, Pincode is exists.")},
                        status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***************
    Delete Pincode
***************
"""


class Hard_Delete_Pincode_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    serializer_class = Pincode_serializers

    def get_object(self, pk):
        try:
            return Pincode_DB.objects.get(pk=pk)
        except Pincode_DB.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Pincode"], operation_description="Super admin & Admin will delete Booking SLot, using by this api",)
    def delete(self, request, pk, format=None):

        # # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        Pincode_for_del = self.get_object(pk)

        if Pincode_for_del.is_active == True:

            Pincode_for_del.is_active = False

            Pincode_for_del.save()

            Pincode_DB.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
***************
   Active Deleted Pincode
***************
"""


class Active_Deleted_Pincode_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = Pincode_serializers

    def get_object(self, pk):
        try:
            return Pincode_DB.objects.get(pk=pk)
        except Pincode_DB.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Pincode"], operation_description="Super admin & Admin will active delete pincode",)
    def get(self, request, pk, format=None):

        # # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        Pincode_for_del = self.get_object(pk)

        if Pincode_for_del.is_active == False:

            Pincode_for_del.is_active = True

            Pincode_for_del.save()

            Pincode_DB.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Activated")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Activate")},
                status=status.HTTP_400_BAD_REQUEST)


"""
***************
   Active CLB PickUp Pincode
***************
"""


class Active_CLBPickup_Pincode_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = Pincode_serializers

    def get_object(self, pk):
        try:
            return Pincode_DB.objects.get(pk=pk)
        except Pincode_DB.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Pincode"], operation_description="Super admin & Admin will active delete pincode",)
    def get(self, request, pincode, format=None):
        try:
            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            PincodeList = Pincode_DB.objects.filter(
                Q(pincode=pincode) & Q(is_active=True)).order_by("id")

            if len(PincodeList) > 0:
                Pincode_DB.objects.filter(
                    Q(pincode=pincode) & Q(is_active=True)).update(is_clb_pickup=True, updated_by=str(UserID))

                return Response(
                    {"response_code": 200,
                        'response_message': _("Successfully Updated"), },
                    status=status.HTTP_200_OK)
            else:
                return Response(
                    {"response_code": 404,
                     'response_message': _("Data Not found"), },
                    status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***************
   Deactive CLB PickUp Pincode
***************
"""


class dective_CLBPickup_Pincode_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]
    serializer_class = Pincode_serializers

    def get_object(self, pk):
        try:
            return Pincode_DB.objects.get(pk=pk)
        except Pincode_DB.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Pincode"], operation_description="Super admin & Admin will active delete pincode",)
    def get(self, request, pincode, format=None):
        try:
            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            PincodeList = Pincode_DB.objects.filter(
                Q(pincode=pincode) & Q(is_active=True)).order_by("id")

            if len(PincodeList) > 0:
                Pincode_DB.objects.filter(
                    Q(pincode=pincode) & Q(is_active=True)).update(is_clb_pickup=False,  updated_by=str(UserID))

                return Response(
                    {"response_code": 200,
                        'response_message': _("Successfully Updated"), },
                    status=status.HTTP_200_OK)
            else:
                return Response(
                    {"response_code": 404,
                     'response_message': _("Data Not found"), },
                    status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Search Admin User 
********************
"""


class Search_pincode_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = Pincode_DB.objects.filter(is_active=True)
    serializer_class = Pincode_serializers
    filter_backends = [SearchFilter]
    search_fields = ["pincode", "Area_Name", "City",
                     "State", "Country", ]


"""
****************************************************************************************************************************************************************
                                                                    Agent
****************************************************************************************************************************************************************
"""


"""
********************
    Agent - Verify KYC & Bank
********************
"""


class Agent_Verify_KYC_byAdmin_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    serializer_class = Agent_Verify_KYC_byAdmin_Serializers
    # parser_classes = [MultiPartParser]

    def get_object(self, pk):
        try:
            return Agent_KYC.objects.get(pk=pk)
        except Agent_KYC.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Agent Verification"], operation_description="Agent  kyc Verification",)
    def patch(self, request, pk, format=None):
        try:
            KYC_ID = self.get_object(pk)

            # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(KYC_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                # user_data = serializer.data
                Agent_KYC.objects.filter(
                    id=serializer.data['id']).update(updated_by=str(UserID), is_verify_by=str(UserID))

                """===================== Encrypt & Decrypt Data ====================="""

                SendEmail.send_email({
                    "email_body": "Hello Your KYC is verified",
                    "to_email": Agent_KYC.objects.get(
                        id=serializer.data['id']).user_idKYC.email,
                    "email_subject": "verify your Accountaa",
                })

                return Response({
                    "response_code": 200,
                    "response_message": _("Successfully"),
                    "response_data": encrypt_data(OrderDict_to_json(serializer.data)), },
                    status=status.HTTP_200_OK)
            else:
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


class Agent_Verify_Bank_byAdmin_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    serializer_class = Agent_Verify_Bank_byAdmin_Serializers
    # parser_classes = [MultiPartParser]

    def get_object(self, pk):
        try:
            return Agent_Bank_Details.objects.get(pk=pk)
        except Agent_Bank_Details.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Agent Verification"], operation_description="Agent  kyc Verification",)
    def patch(self, request, pk, format=None):
        try:
            bank_ID = self.get_object(pk)

            # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(bank_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                # user_data = serializer.data
                Agent_Bank_Details.objects.filter(
                    id=serializer.data['id']).update(updated_by=str(UserID), is_verify_by=str(UserID), )
                """===================== Encrypt & Decrypt Data ====================="""

                return Response({
                    "response_code": 200,
                    "response_message": _("Successfully"),
                    "response_data": encrypt_data(OrderDict_to_json(serializer.data)), },
                    status=status.HTTP_200_OK)
            else:
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Agent - Soft Delete
********************
"""


class softDelete_Agent_User_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowSuperAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = GetUserDetails_serializers

    queryset = User.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Soft Delete User"], operation_description="Get Admin User Details",)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        user_id_for_del = self.get_object(pk)

        if not user_id_for_del.is_superuser and not user_id_for_del.is_staff:
            if user_id_for_del.user_type == "Agent":
                if user_id_for_del.is_active == True and user_id_for_del.is_verify == True:

                    user_id_for_del.is_active = False
                    user_id_for_del.is_verify = False

                    user_id_for_del.save()

                    Agent_Bank_Details.objects.filter(user_idBank=user_id_for_del).update(
                        is_verify=False, is_active=False, updated_by=str(UserID))

                    Agent_KYC.objects.filter(user_idKYC=user_id_for_del).update(
                        is_verify=False, is_active=False, updated_by=str(UserID))

                    Agent_Address.objects.filter(user_idAddress=user_id_for_del).update(
                        is_active=False, updated_by=str(UserID))

                    User.objects.filter(id=pk).update(
                        updated_by=str(UserID))

                    return Response(
                        {"responseCode": 200,
                         'responseMessage': _("Successfully Deleted")},
                        status=status.HTTP_200_OK)

                return Response(
                    {"responseCode": 400,
                     'responseMessage':  _("Already Is Deleted")},
                    status=status.HTTP_400_BAD_REQUEST)

            return Response(
                {"responseCode": 400,
                 'responseMessage':  _("You cannot delete user except Agent.")},
                status=status.HTTP_400_BAD_REQUEST)

        return Response(
            {"responseCode": 400,
             'responseMessage':  _("You cannot delete ADMIN User.")},
            status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Agent - Verify - List
********************
"""


class Get_Verify_agent_Details(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowSuperAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = GetUserDetails_serializers

    @ swagger_auto_schema(tags=["Get User Details"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):

        VerifyAgent = User.objects.filter(Q(is_active=True) & Q(is_verify=True) & Q(
            is_staff=False) & Q(is_superuser=False) & Q(user_type="Agent"))

        if VerifyAgent:
            serializer = self.serializer_class(
                VerifyAgent, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Agent - unVerify - List
********************
"""


class Get_unVerify_agent_Details(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowSuperAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = GetUserDetails_serializers

    @ swagger_auto_schema(tags=["Get User Details"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):

        VerifyAgent = User.objects.filter(Q(is_active=False) & Q(is_verify=False) & Q(
            is_staff=False) & Q(is_superuser=False) & Q(user_type="Agent"))

        if VerifyAgent:
            serializer = self.serializer_class(
                VerifyAgent, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Agent - Verify KYC  - List
********************
"""


class Agent_All_Verified_KYC_List_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = Agent_KYC_for_admin_Serializers

    def get_object(self, pk):
        # Returns an object instance that should
        # be used for detail views.
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Agent Bank and KYC Details by ID"], operation_description="Get Admin User Details",)
    def get(self, request, pk, format=None):

        UserID = self.get_object(pk)

        KYCList = Agent_KYC.objects.filter(Q(is_active=True) & Q(is_verify=True) & Q(
            user_idKYC=UserID)).order_by("id")

        serializer = self.serializer_class(
            KYCList, many=True, context={"request": request})

        if len(serializer.data) > 0:
            return Response(
                {"code": 200,
                 'message': _("Success"),
                 'data': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"code": 404,
                 'message': _("Data Not found"),
                 'data': serializer.data},
                status=status.HTTP_404_NOT_FOUND)


class Agent_All_UNverified_KYC_List_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = Agent_KYC_for_admin_Serializers

    def get_object(self, pk):
        # Returns an object instance that should
        # be used for detail views.
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Agent Bank and KYC Details by ID"], operation_description="Get Admin User Details",)
    def get(self, request, pk, format=None):

        UserID = self.get_object(pk)

        KYCList = Agent_KYC.objects.filter(Q(is_verify=False) & Q(
            user_idKYC=UserID)).order_by("id")

        serializer = self.serializer_class(
            KYCList, many=True, context={"request": request})

        if len(serializer.data) > 0:
            return Response(
                {"code": 200,
                 'message': _("Success"),
                 'data': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"code": 404,
                 'message': _("Data Not found"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Agent - Verify Bank  - List
********************
"""


class Agent_All_Verified_Bank_List_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Agent_Bank_Details_for_admin_Serializers

    def get_object(self, pk):

        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Agent Bank and KYC Details by ID"], operation_description="Get Admin User Details",)
    def get(self, request, pk, format=None):

        UserID = self.get_object(pk)

        KYCList = Agent_Bank_Details.objects.filter(Q(is_active=True) & Q(is_verify=True) & Q(
            user_idBank=UserID)).order_by("id")

        serializer = self.serializer_class(
            KYCList, many=True, context={"request": request})

        if len(serializer.data) > 0:
            return Response(
                {"code": 200,
                 'message': _("Success"),
                 'data': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"code": 404,
                 'message': _("Data Not found"), },
                status=status.HTTP_404_NOT_FOUND)


class Agent_All_UNverified_bank_List_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Agent_Bank_Details_for_admin_Serializers

    def get_object(self, pk):
        # Returns an object instance that should
        # be used for detail views.
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Agent Bank and KYC Details by ID"], operation_description="Get Admin User Details",)
    def get(self, request, pk, format=None):

        UserID = self.get_object(pk)

        KYCList = Agent_Bank_Details.objects.filter(Q(is_verify=False) & Q(
            user_idBank=UserID)).order_by("id")

        serializer = self.serializer_class(
            KYCList, many=True, context={"request": request})

        if len(serializer.data) > 0:
            return Response(
                {"code": 200,
                 'message': _("Success"),
                 'data': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"code": 404,
                 'message': _("Data Not found"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Search Agent User 
********************
"""


class Search_AgentUser_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = User.objects.filter(Q(is_active=True) & Q(user_type="Agent"))
    serializer_class = Search_User_Serializres
    filter_backends = [SearchFilter]
    search_fields = ["first_name", "middle_name", "last_name",
                     "username", "phone", "email", ]


"""
********************
    Search End User 
********************
"""


class Search_EndUser_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = User.objects.filter(Q(is_active=True) & Q(user_type="EndUser"))
    serializer_class = Search_User_Serializres
    filter_backends = [SearchFilter]
    search_fields = ["first_name", "middle_name", "last_name",
                     "username", "phone", "email", ]


"""
****************************************************************************************************************************************************************
                                                                     Courier Company
****************************************************************************************************************************************************************
"""


"""
****************
    Create Courier Company by Admin
****************
"""


class Register_Courier_Company_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]

    serializer_class = Courier_Company_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Courier Company"], operation_description=("Payload:", '{"name": "String","address": " Text Field String","GST_number":"String","PanCard_number": "String","contact_person_name": "String","contact_number": "String","email": "String","website": "String"}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 201,
                    "response_message": _("Courier company is listed"),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('GSTNumber_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("GST number already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Pan_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Pan Card number is already existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('email_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Email is already existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('website_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("WebSite is already exists.")},
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

                elif serializer.errors.get('GST_Validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Invalid GST Number please Enter Correct. ')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Pancard_Validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Invalid PanCard Number please Enter Correct.')},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Update Courier Company by Admin
****************
"""


class Update_Courier_Profile_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]

    serializer_class = Courier_Company_Serializers

    def get_object(self, pk):
        try:
            return CourierCompany.objects.get(pk=pk)
        except CourierCompany.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Courier Company"], operation_description=("Payload:", '{"name": "String","address": " Text Field String","GST_number":"String","PanCard_number": "String","contact_person_name": "String","contact_number": "String","email": "String","website": "String"}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                CourierCompany.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("Courier profile has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('GSTNumber_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("GST number already is existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Pan_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Pan Card number is already existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('email_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Email is already existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('website_exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("WebSite is already exists.")},
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

                elif serializer.errors.get('GST_Validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Invalid GST Number please Enter Correct. ')},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Pancard_Validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _('Invalid PanCard Number please Enter Correct.')},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Get All Courier Company by Admin
****************
"""


class Get_All_Coruier_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]

    serializer_class = Courier_Copmany_List_Delete_serializers

    @swagger_auto_schema(tags=["Courier Company"], operation_description="Get All data - is admin ",)
    def get(self, request, format=None):
        Courier_Company_Data = CourierCompany.objects.filter(is_active=True)

        if Courier_Company_Data:
            serializer = self.serializer_class(
                Courier_Company_Data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Get Singal Courier Company by Admin
****************
"""


class Get_Singal_Coruier_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Courier_Copmany_List_Delete_serializers

    def get_object(self, pk):
        try:
            return CourierCompany.objects.get(pk=pk)
        except CourierCompany.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Courier Company"], operation_description="Get All data - is admin ",)
    def get(self, request, pk, format=None):

        Courier_Company_id = self.get_object(pk)

        if Courier_Company_id.is_active == True:

            serializer = self.serializer_class(
                Courier_Company_id,  context={"request": request})
            # 'responseData': encrypt_data(serializer.data)},
            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    SoftDelete Courier Company by Admin
****************
"""


class Delete_Soft_Courier_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [AllowSuperAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Courier_Copmany_List_Delete_serializers

    queryset = CourierCompany.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return CourierCompany.objects.get(pk=pk)
        except CourierCompany.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Courier Company"], operation_description="Soft Delete - Super admin ",)
    def delete(self, request, pk, format=None):

        # # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        Courier_id_for_del = self.get_object(pk)

        if Courier_id_for_del.is_active == True:

            Courier_id_for_del.is_active = False

            Courier_id_for_del.save()

            CourierCompany.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Search Coureir Company
********************
"""


class Search_Courier_Company_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = CourierCompany.objects.filter(
        Q(is_active=True))
    serializer_class = Courier_Copmany_List_Delete_serializers
    filter_backends = [SearchFilter]
    search_fields = ["name", "address", "contact_person_name",
                     "email", "website", ]


"""
****************************************************************************************************************************************************************
                                                                    Review CLB and Courier Company
****************************************************************************************************************************************************************
"""


"""
****************
    CLB Review by Rating
****************
"""


class CLB_Review_by_Rating(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(tags=["CLB Review"], operation_description="Only admin User ",)
    def get(self, request, format=None):

        # TotalData = {
        #     "Total Review": CLB_Review.objects.all().count(),
        #     "Total_Avg": CLB_Review.objects.aggregate(Avg("review_answer")),
        #     "Total_Review_by_Rating": CLB_Review.objects.values('review_answer').annotate(
        #         Review_Count=Count('review_answer'))
        # }

        return Response({"responseCode": 200,
                         'responseMessage': _("Success"),
                         'responseData': encrypt_data({
                             "Total Review": CLB_Review.objects.all().count(),
                             "Total_Avg": CLB_Review.objects.aggregate(Avg("review_answer")),
                             "Total_Review_by_Rating": CLB_Review.objects.values('review_answer').annotate(
                                 Review_Count=Count('review_answer'))
                         })}, status=status.HTTP_200_OK)


"""
****************
    Delete CLB Review
****************
"""


class Hard_Delete_CLB_Review_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [AllowSuperAdminUser]
    permission_classes = [permissions.AllowAny]
    serializer_class = CLB_Review_Serializers

    def get_object(self, pk):
        try:
            return CLB_Review.objects.get(pk=pk)
        except CLB_Review.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["CLB Review"], operation_description="Only super admin User ",)
    def delete(self, request, pk, format=None):
        Mark_ID = self.get_object(pk)
        Mark_ID.delete()
        return Response(
            {"responseCode": 200,
             'responseMessage': _("Successfully Deleted")},
            status=status.HTTP_200_OK)


"""
*****************
    List CLB Review by Rating
*****************
"""


class List_CLB_Review_by_Rating_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    serializer_class = CLB_Review_Serializers

    @swagger_auto_schema(tags=["CLB Review"], operation_description="CLB Review list",)
    def get(self, request, rating, format=None):
        Review_Data = CLB_Review.objects.filter(
            review_answer=rating).order_by("id")

        serializer = self.serializer_class(
            Review_Data, many=True, context={"request": request})

        return Response(
            {"code": 200,
             'message': _("Success"),
             'data': encrypt_data(OrderDict_to_json(serializer.data))
             },
            status=status.HTTP_200_OK)


"""
****************
    CLB Review by Rating
****************
"""


class CourierCompany_Review_by_Company(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    @swagger_auto_schema(tags=["CLB Review"], operation_description="Only admin User ",)
    def get(self, request, format=None):

        # TotalData = {
        #     "Raview_of_Corier_Company": CourierCompany.objects.values('name').annotate(
        #         average_rating=Avg('ReviewCCId__review_answer'), average_Count=Count('ReviewCCId__review_answer')),        }

        return Response({"responseCode": 200,
                         'responseMessage': _("Success"),
                         'responseData': encrypt_data(CourierCompany.objects.values('name').annotate(
                             average_rating=Avg('ReviewCCId__review_answer'), average_Count=Count('ReviewCCId__review_answer'))), }, status=status.HTTP_200_OK)


"""
****************
    Delete Courier Company Review
****************
"""


class Hard_Delete_Courier_Company_Review_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [AllowSuperAdminUser]
    permission_classes = [permissions.AllowAny]
    serializer_class = Courier_Company_Review_Serializers

    def get_object(self, pk):
        try:
            return Courier_Company_Review.objects.get(pk=pk)
        except Courier_Company_Review.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["CLB Review"], operation_description="Only super admin User ",)
    def delete(self, request, pk, format=None):
        Mark_ID = self.get_object(pk)
        Mark_ID.delete()
        return Response(
            {"responseCode": 200,
             'responseMessage': _("Successfully Deleted")},
            status=status.HTTP_200_OK)


"""
*****************
    List CLB Review by Rating
*****************
"""


class ListReviewByCompany_Review(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    serializer_class = Courier_Company_Review_Serializers

    @swagger_auto_schema(tags=["CLB Review"], operation_description="CLB Review list",)
    def get(self, request, Cou_Com_id, format=None):
        Review_Data = Courier_Company_Review.objects.filter(
            CC_id=Cou_Com_id).order_by("id")

        serializer = self.serializer_class(
            Review_Data, many=True, context={"request": request})

        return Response(
            {"code": 200,
             'message': _("Success"),
             "data": encrypt_data({
                 "Courier_Company_Name": CourierCompany.objects.get(id=Cou_Com_id).name,
                 "Avg_Review": CourierCompany.objects.filter(id=Cou_Com_id).aggregate(
                     average_rating=Avg('ReviewCCId__review_answer'), average_Count=Count('ReviewCCId__review_answer')),
                 "Review_Details": OrderDict_to_json(serializer.data)
             },)},
            status=status.HTTP_200_OK)


"""
****************************************************************************************************************************************************************
                                                                     Price
****************************************************************************************************************************************************************
"""


"""
****************
    Create Price for Customer
****************
"""


class Create_Price_for_Customer_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CreatePriceForCustomer_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Price"], operation_description=("Payload:", '{"CC_Price_id": int, "ServiceType": "string","ShipmentType": "String","TravelBy": "String","Weight_From": int,"Weight_To": int,"Local": int,"State": int,"RestOfIndia": int,}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Decode JWT  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]
                PriceForCustomer.objects.filter(
                    id=user_data["id"]).update(created_by=str(UserID))
                return Response({
                    "response_code": 201,
                    "response_message": _("Courier company is listed"),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('Courier_Company_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Courier Company does not existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ServiceType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Service Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ShipmentType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Shipment Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Validation
                elif serializer.errors.get('Invalid_TravelType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Travel Type.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Weight_Limit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Weight should be between 0 to 1000")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Update Price for Customer
****************
"""


class Update_Price_for_Customer_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CreatePriceForCustomer_Serializers

    def get_object(self, pk):
        try:
            return PriceForCustomer.objects.get(pk=pk)
        except PriceForCustomer.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Price"], operation_description=("Payload:", '{"CC_Price_id": int, "ServiceType": "string","ShipmentType": "String","TravelBy": "String","Weight_From": int,"Weight_To": int,"Local": int,"State": int,"RestOfIndia": int,}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                PriceForCustomer.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("Price has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('Courier_Company_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Courier Company does not existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ServiceType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Service Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ShipmentType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Shipment Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Validation
                elif serializer.errors.get('Invalid_TravelType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Travel Type.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Weight_Limit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Weight should be between 0 to 1000")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    SoftDelete Price for Customer
****************
"""


class Delete_Soft_Price_For_Customer_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = ListPriceForCustomer_Serializers

    queryset = PriceForCustomer.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return PriceForCustomer.objects.get(pk=pk)
        except PriceForCustomer.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Price"], operation_description="Soft Delete - Super admin ",)
    def delete(self, request, pk, format=None):

        # # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        Price_id_for_del = self.get_object(pk)

        if Price_id_for_del.is_active == True:

            Price_id_for_del.is_active = False

            Price_id_for_del.save()

            PriceForCustomer.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Get Price for Customer
****************
"""


class Get_Price_List_of_Customer_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = ListPriceForCustomer_Serializers

    def get_object(self, pk):
        # Returns an object instance that should
        # be used for detail views.
        try:
            return PriceForCustomer.objects.get(pk=pk)
        except PriceForCustomer.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Price"], operation_description="Soft Delete - Super admin ",)
    def get(self, request, pk, format=None):
        SubCateList = PriceForCustomer.objects.filter(Q(is_active=True) & Q(
            CC_Price_id=pk)).order_by("id")

        serializer = self.serializer_class(
            SubCateList, many=True, context={"request": request})

        if len(serializer.data) > 0:
            return Response(
                {"code": 200,
                 'message': _("Success"),
                 'data': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"code": 404,
                 'message': _("Data Not found"),
                 'data': serializer.data},
                status=status.HTTP_404_NOT_FOUND)


"""
***************************************
***************************************
"""


"""
****************
    Create Price for Us
****************
"""


class Create_Price_for_Us_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CreatePriceForUS_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Price"], operation_description=("Payload:", '{"CC_OurPrice_id": int, "ServiceType": "string","ShipmentType": "String","TravelBy": "String","Weight_From": int,"Weight_To": int,"Local": int,"State": int,"RestOfIndia": int,}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Decode JWT  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                Our_Price.objects.filter(
                    id=user_data["id"]).update(created_by=str(UserID))

                return Response({
                    "response_code": 201,
                    "response_message": _("Courier company is listed"),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('Courier_Company_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Courier Company does not existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ServiceType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Service Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ShipmentType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Shipment Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Validation
                elif serializer.errors.get('Invalid_TravelType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Travel Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Weight_Limit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Weight should be between 0 to 1000")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Update Price for US
****************
"""


class Update_Price_for_US_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CreatePriceForUS_Serializers

    def get_object(self, pk):
        try:
            return Our_Price.objects.get(pk=pk)
        except Our_Price.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Price"], operation_description=("Payload:", '{"CC_Price_id": int, "ServiceType": "string","ShipmentType": "String","TravelBy": "String","Weight_From": int,"Weight_To": int,"Local": int,"State": int,"RestOfIndia": int,}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                Our_Price.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("Price has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('Courier_Company_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Courier Company does not existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ServiceType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Service Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Invalid_ShipmentType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Shipment Type.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Validation
                elif serializer.errors.get('Invalid_TravelType'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Travel Type.")},
                        status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Weight_Limit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Weight should be between 0 to 1000")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    SoftDelete Price for us
****************
"""


class Delete_Soft_Price_For_us_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = ListPriceForUs_Serializers

    queryset = Our_Price.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return Our_Price.objects.get(pk=pk)
        except Our_Price.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Price"], operation_description="Soft Delete - Super admin ",)
    def delete(self, request, pk, format=None):

        # # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        Price_id_for_del = self.get_object(pk)

        if Price_id_for_del.is_active == True:

            Price_id_for_del.is_active = False

            Price_id_for_del.save()

            Our_Price.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Get Price for US
****************
"""


class Get_Price_List_of_US_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = ListPriceForUs_Serializers

    def get_object(self, pk):
        # Returns an object instance that should
        # be used for detail views.
        try:
            return Our_Price.objects.get(pk=pk)
        except Our_Price.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Price"], operation_description="Soft Delete - Super admin ",)
    def get(self, request, pk, format=None):
        SubCateList = Our_Price.objects.filter(Q(is_active=True) & Q(
            CC_OurPrice_id=pk)).order_by("id")

        serializer = self.serializer_class(
            SubCateList, many=True, context={"request": request})

        if len(serializer.data) > 0:
            return Response(
                {"code": 200,
                 'message': _("Success"),
                 'data': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"code": 404,
                 'message': _("Data Not found"),
                 'data': serializer.data},
                status=status.HTTP_404_NOT_FOUND)


"""
****************************************************************************************************************************************************************
                                                                Frequently Asked Questions
****************************************************************************************************************************************************************
"""


"""
****************
FAQ Category    - Create
****************
"""


class Create_FAQ_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = faq_category_encrypt_serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["FAQ"], operation_description=("Payload:", '{"name": "string",}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Decode JWT  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                FAQ_Cateogry.objects.filter(
                    id=user_data["id"]).update(created_by=str(UserID))

                return Response({
                    "response_code": 201,
                    "response_message": _("FAQ's Category has been created"),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('name_alpha'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Category must be entered only alphbet.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
FAQ Category    - Update
****************
"""


class Update_FAQ_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = faq_category_encrypt_serializers

    def get_object(self, pk):
        try:
            return FAQ_Cateogry.objects.get(pk=pk)
        except FAQ_Cateogry.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["FAQ"], operation_description=("Payload:", '{"name": "string",}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                FAQ_Cateogry.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("FAQ's Category has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('name_alpha'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Category must be entered only alphbet.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
FAQ Category    - Delete
****************
"""


class DeleteSoft_FAQ_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = faq_category_serializers

    queryset = FAQ_Cateogry.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return FAQ_Cateogry.objects.get(pk=pk)
        except FAQ_Cateogry.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["FAQ"], operation_description="Soft Delete  ",)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        id_ForDel = self.get_object(pk)

        if id_ForDel.is_active == True:

            id_ForDel.is_active = False

            id_ForDel.save()

            FAQ.objects.filter(faq_category_id=id_ForDel).update(
                is_active=False)
            FAQ_Cateogry.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
FAQ Category    - Single data 
****************
"""


class Get_FAQ_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [OnlyEndUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = faq_category_serializers

    def get_object(self, pk):
        try:
            return FAQ_Cateogry.objects.get(pk=pk)
        except FAQ_Cateogry.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["FAQ"], operation_description=("List Data ",))
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
FAQ Category    - List ALL 
****************
"""


class List_FAQ_Category_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = faq_category_serializers

    @ swagger_auto_schema(tags=["FAQ"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        data = FAQ_Cateogry.objects.filter(is_active=True)

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************************************************************************
********************************************************************************
"""


"""
****************
FAQ    - Create
****************
"""


class Create_FAQ_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = faq_ecrypt_serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["FAQ"], operation_description=("Payload:", '{"faq_category_id": int, "question": "string", "answer": "string"}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Decode JWT  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                FAQ.objects.filter(
                    id=user_data["id"]).update(created_by=str(UserID))

                return Response({
                    "response_code": 201,
                    "response_message": _("FAQ has been created"),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('FAQCategory_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("FAQ Category does not existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
FAQ     - Update
****************
"""


class Update_FAQ_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = faq_ecrypt_serializers

    def get_object(self, pk):
        try:
            return FAQ.objects.get(pk=pk)
        except FAQ.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["FAQ"], operation_description=("Payload:", '{"name": "string",}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                FAQ.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("FAQ has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('FAQCategory_Exists'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("FAQ Category does not existed.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
FAQ     - Delete  
****************
"""


class DeleteSoft_FAQ_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = faq_serializers

    queryset = FAQ.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return FAQ.objects.get(pk=pk)
        except FAQ.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["FAQ"], operation_description="Soft Delete  ",)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        id_ForDel = self.get_object(pk)

        if id_ForDel.is_active == True:

            id_ForDel.is_active = False

            id_ForDel.save()

            FAQ.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
FAQ     - List - All 
****************
"""


class List_FAQ_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = faq_serializers

    @ swagger_auto_schema(tags=["FAQ"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        data = FAQ.objects.filter(is_active=True)

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
FAQ     - List - Single 
****************
"""


class Get_FAQ_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [OnlyEndUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = faq_serializers

    def get_object(self, pk):
        try:
            return FAQ.objects.get(pk=pk)
        except FAQ.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["FAQ"], operation_description=("List Data ",))
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************************************************************************
********************************************************************************
"""


"""
****************
FAQ - List  search with category id 
****************
"""


class Get_FAQ_Category_With_QA_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = faq_serializers

    def get_object(self, pk):
        # Returns an object instance that should
        # be used for detail views.
        try:
            return FAQ_Cateogry.objects.get(pk=pk)
        except FAQ_Cateogry.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["FAQ"], operation_description="Soft Delete - Super admin ",)
    def get(self, request, pk, format=None):

        SubCateList = FAQ.objects.filter(Q(is_active=True) & Q(
            faq_category_id=pk)).order_by("id")

        serializer = self.serializer_class(
            SubCateList, many=True, context={"request": request})

        if len(serializer.data) > 0:
            return Response(
                {"code": 200,
                 'message': _("Success"),
                 'data': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"code": 404,
                 'message': _("Data Not found"),
                 'data': serializer.data},
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Search FAQ
********************
"""


class Search_FAQ_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = FAQ.objects.filter(is_active=True)
    serializer_class = faq_serializers
    filter_backends = [SearchFilter]
    search_fields = ['faq_category_id__name',
                     "question",
                     "answer",
                     ]


"""
****************************************************************************************************************************************************************
                                                                Contact Us
****************************************************************************************************************************************************************
"""


"""
****************
    Create Contact Us 
****************
"""


class Create_ContactUs_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = CountactUs_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Contact Us"], operation_description=("Hello"),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Send Email to Admin ====================="""

                SendEmail.send_email({
                    "email_body": user_data['description'],
                    "to_email": "avinash.smcs@gmail.com",
                    "email_subject": user_data['subject']})

                return Response({
                    "response_code": 201,
                    "response_message": _("Thanks for visting contact us and your query has been sent to admin"),
                    "response_data": encrypt_data(serializer.data)},

                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('email_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Please, Enter the correct E-Mail.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Country_Code'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Country must be start with '+', and Numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Phonelength'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone must be bewtween 10  to 15 Characters")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Solve Contact Us 
****************
"""


class Update_ContactUs_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CountactUs_Update_Serializers

    def get_object(self, pk):
        try:
            return ContactUs.objects.get(pk=pk)
        except ContactUs.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Contact Us"], operation_description=("Payload:", '{"name": "string",}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Status Change  ====================="""

                ContactUs.objects.filter(
                    id=pk).update(updated_by=str(UserID), solve_by=str(UserID), solve_timeshtamp=datetime.datetime.now())

                return Response({
                    "response_code": 200,
                    "response_message": _("Checked Contac Us"),
                    "response_data": encrypt_data(user_data), },
                    status=status.HTTP_200_OK)

            else:

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
   Delete Contact Us 
****************
"""


class DeleteSoft_ContactUs_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CountactUs_Serializers

    queryset = ContactUs.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return ContactUs.objects.get(pk=pk)
        except ContactUs.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Contact Us"], operation_description="Soft Delete  ",)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        id_ForDel = self.get_object(pk)

        if id_ForDel.is_active == True:

            id_ForDel.is_active = False

            id_ForDel.save()

            ContactUs.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
FAQ     - List - All 
****************
"""


class List_ContactUs_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CountactUs_Serializers

    @ swagger_auto_schema(tags=["Contact Us"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        data = ContactUs.objects.filter(is_active=True)

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
FAQ     - List - Single 
****************
"""


class Get_ContactUs_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]

    serializer_class = CountactUs_Serializers

    def get_object(self, pk):
        try:
            return ContactUs.objects.get(pk=pk)
        except ContactUs.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Contact Us"], operation_description=("List Data ",))
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Search Contact us
********************
"""


class Search_Contact_Us_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = ContactUs.objects.filter(is_active=True).order_by("id")
    serializer_class = CountactUs_Serializers
    filter_backends = [SearchFilter]
    search_fields = ['name', "phone", "email", "subject", "description"]


"""
****************************************************************************************************************************************************************
                                                                Issue / Ticket / Support 
****************************************************************************************************************************************************************
"""


"""
****************
Issue Category    - Create
****************
"""


class Create_Issue_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = issue_Category_encrypt_serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Issue Category"], operation_description=("Payload:", '{"name": "string",}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Decode JWT  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                Issue_Category.objects.filter(
                    id=user_data["id"]).update(created_by=str(UserID))

                return Response({
                    "response_code": 201,
                    "response_message": _("Issue's Category has been created"),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('name_alpha'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Category must be entered only alphbet.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
Issue Category    - Update
****************
"""


class Update_Issue_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = issue_Category_encrypt_serializers

    def get_object(self, pk):
        try:
            return Issue_Category.objects.get(pk=pk)
        except Issue_Category.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Issue Category"], operation_description=("Payload:", '{"name": "string",}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                Issue_Category.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("Issue's Category has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('name_alpha'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Category must be entered only alphbet.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
Issue Category    - Delete
****************
"""


class DeleteSoft_Issue_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = issue_Category_serializers

    queryset = Issue_Category.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return Issue_Category.objects.get(pk=pk)
        except Issue_Category.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Issue Category"], operation_description="Soft Delete  ",)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        id_ForDel = self.get_object(pk)

        if id_ForDel.is_active == True:

            id_ForDel.is_active = False

            id_ForDel.save()

            Issue_Category.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
Issue Category    - Single data 
****************
"""


class Get_Issue_Category_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = issue_Category_serializers

    def get_object(self, pk):
        try:
            return Issue_Category.objects.get(pk=pk)
        except Issue_Category.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Issue Category"], operation_description=("List Data ",))
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
Issue Category    - List ALL 
****************
"""


class List_Issue_Category_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = issue_Category_serializers

    @ swagger_auto_schema(tags=["Issue Category"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        data = Issue_Category.objects.filter(is_active=True)

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************************************************************************************************************************************************************
                                                                 Ticket / Support 
****************************************************************************************************************************************************************
"""


"""
*****************
    Open - List  Support Ticket 
*****************
"""


class List_Open_Support_Ticket_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = admin_SupportTicket_Serializers

    @ swagger_auto_schema(tags=["Support Ticket - Admin"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):

        data = Support_Ticket.objects.filter(
            Q(is_active=True) & Q(status="Open") & Q(is_closed=False))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
*****************
    In_Progress  - List  Support Ticket 
*****************
"""


class List_In_Progress_Support_Ticket_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = admin_SupportTicket_Serializers

    @ swagger_auto_schema(tags=["Support Ticket - Admin"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):

        data = Support_Ticket.objects.filter(
            Q(is_active=True) & Q(status="In_Progress") & Q(is_closed=False))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
*****************
    Closed  - List  Support Ticket 
*****************
"""


class List_Closed_Support_Ticket_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = admin_SupportTicket_Serializers

    @ swagger_auto_schema(tags=["Support Ticket - Admin"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):

        data = Support_Ticket.objects.filter(
            Q(is_active=True) & Q(status="Closed") & Q(is_closed=True))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
Support     - List - Single 
****************
"""


class Get_SupportTicket_AdminViews(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = admin_SupportTicket_Serializers

    def get_object(self, pk):
        try:
            return Support_Ticket.objects.get(pk=pk)
        except Support_Ticket.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Support Ticket - Admin"], operation_description="Get Admin User Details",)
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
*****************
   Update Support Ticket 
*****************
"""


class Update_Support_Ticket_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = SupportTicket_Admin_Encrypt_Serializres

    def get_object(self, pk):
        try:
            return Support_Ticket.objects.get(pk=pk)
        except Support_Ticket.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Support Ticket - Admin"], operation_description="Get Admin User Details",)
    def patch(self, request, pk, format=None):
        try:
            if Support_Ticket.objects.get(pk=pk).is_closed:
                return Response({
                    "response_code": 400,
                    "response_message": _("Already, ticketed is closed.")},
                    status=status.HTTP_400_BAD_REQUEST)

            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                Support_Ticket.objects.filter(
                    id=pk).update(updated_by=str(UserID), closed_by=str(UserID), closing_timestamp=datetime.datetime.now())

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                """===================== Email to user ====================="""

                return Response({
                    "response_code": 200,
                    "response_message": _("FAQ's Category has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('isClose_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Is_close is False, please check True it")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('close_Detail'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Close details must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('isClose_validation_else'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Is_close is True, please check False it")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('close_Detail_else'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Close details must be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)
                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Search Support
********************
"""


class Search_Support_Ticket_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = Support_Ticket.objects.filter(is_active=True).order_by("id")
    serializer_class = admin_SupportTicket_Serializers
    filter_backends = [SearchFilter]
    search_fields = ['ticket_no',  "requester_phone", "requester_email", "issue_Cate_id__Catename", "subject",
                     "description", "order_id", "closing_details", "client_User_Id__first_name", "client_User_Id__last_name", ]


"""
****************************************************************************************************************************************************************
                                                                 Notification
****************************************************************************************************************************************************************
"""


"""
****************
    Create Notification
****************
"""


class Create_Notification_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = Notification_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Notification"], operation_description=("Payload:", '{"name": "string",}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Decode JWT  ====================="""
                # print(
                # f"\n\n\n\n Before send notification \n \n\n  {user_data}\n\n\n\n\n")

                sendPush(
                    usersType=user_data["usersType"], title=user_data["title"], msg=user_data["body"])

                """===================== Decode JWT  ====================="""
                # token = self.request.headers["Authorization"]
                # UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Notification.objects.filter(
                #     id=user_data["id"]).update(created_by=str(UserID))

                return Response({
                    "response_code": 201,
                    "response_message": _("Notification has been send."),
                    "response_data": user_data},
                    status=status.HTTP_201_CREATED)
            else:

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    List of Notification 
****************
"""


class List_Notification_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Notification_Serializers

    @swagger_auto_schema(tags=["Notification"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Notification.objects.filter(
            Q(is_active=True))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Notification List - Single 
****************
"""


class Get_Notification_AdminViews(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Notification_Serializers

    def get_object(self, pk):
        try:
            return Notification.objects.get(pk=pk)
        except Notification.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Notification"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                # 'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
Notification   - Delete
****************
"""


class DeleteSoft_Notification_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Notification_Serializers

    queryset = Notification.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return Notification.objects.get(pk=pk)
        except Notification.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Notification"], operation_description=("Payload:", '{"name": "string",}'),)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        id_ForDel = self.get_object(pk)

        if id_ForDel.is_active == True:

            id_ForDel.is_active = False

            id_ForDel.save()

            Notification.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
********************
    Search Notification
********************
"""


class Search_Notification_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = Notification.objects.filter(is_active=True).order_by("id")
    serializer_class = Notification_Serializers
    filter_backends = [SearchFilter]
    search_fields = ['title',  "body", ]


"""
****************************************************************************************************************************************************************
                                                                 Banner 
****************************************************************************************************************************************************************
"""


"""
****************
    Create Banner
****************
"""


class Create_Banner_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Banner_Encrypt_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"banner_title": "string", "banner_caption": "string", "banner_start": "yyyy-mm-dd hh:mm:ss", "banner_end": "yyyy-mm-dd hh:mm:ss",}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                # # """===================== Decode JWT  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]
                if "banner_image" in user_data:
                    response_data["banner_image"] = user_data["banner_image"]

                Banner.objects.filter(id=user_data["id"]).update(
                    created_by=str(UserID))
                return Response({
                    "response_code": 201,
                    "response_message": _("Banner has been created."),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('Invalid_Time'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("End time is less than Start Time")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Update Banner 
****************
"""


class Update_Banner_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Banner_Encrypt_Serializers

    def get_object(self, pk):
        try:
            return Banner.objects.get(pk=pk)
        except Banner.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"banner_title": "string", "banner_caption": "string", "banner_start": "yyyy-mm-dd hh:mm:ss", "banner_end": "yyyy-mm-dd hh:mm:ss",}'),)
    def patch(self, request, pk, format=None):
        try:
            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                Banner.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]
                if "banner_image" in user_data:
                    response_data["banner_image"] = user_data["banner_image"]

                return Response({
                    "response_code": 200,
                    "response_message": _("Banner has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors.get('Invalid_Time'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("End time is less than Start Time")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Banner   - Delete
****************
"""


class DeleteSoft_Banner_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = banner_serializers

    queryset = Banner.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return Banner.objects.get(pk=pk)
        except Banner.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"name": "string",}'),)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        id_ForDel = self.get_object(pk)

        if id_ForDel.is_active == True:

            id_ForDel.is_active = False

            id_ForDel.save()

            Banner.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Banner List - Single 
****************
"""


class Get_Banner_AdminViews(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = banner_serializers

    def get_object(self, pk):
        try:
            return Banner.objects.get(pk=pk)
        except Banner.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True or data_id.is_active == False:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                # 'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Banner List - deleted 
****************
"""


class List_deleted_Banner_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = banner_serializers

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Banner.objects.filter(Q(is_active=False))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Banner List - Active 
****************
"""


class List_Active_Banner_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = banner_serializers

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Banner.objects.filter(Q(is_active=True) & Q(
            banner_end__gt=datetime.datetime.now()))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Banner List - Expired 
****************
"""


class List_Expired_Banner_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = banner_serializers

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Banner.objects.filter(Q(is_active=True) & Q(
            banner_end__lt=datetime.datetime.now()))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Banner List - Future 
****************
"""


class List_Future_Banner_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = banner_serializers

    @swagger_auto_schema(tags=["Banner"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Banner.objects.filter(Q(is_active=True) & Q(
            banner_start__gt=datetime.datetime.now()))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Search Banner
********************
"""


class Search_Banner_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = Banner.objects.filter(is_active=True).order_by("id")
    serializer_class = banner_serializers
    filter_backends = [SearchFilter]
    search_fields = ['banner_title',  "banner_caption", ]


"""
****************************************************************************************************************************************************************
                                                                 Offer  
****************************************************************************************************************************************************************
"""


"""
****************
    Create Offer
****************
"""


class Create_Offer_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Offer_discount_encrypt_serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"offer_name": "String", "offer_description": "String", "offer_code": "string", "offer_minium_value" :integer, "offer_start": "date time string ", "offer_end": "date time string ", "offer_percentage": float/decimal value, "offer_upto_value": integer,}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                """===================== Decode JWT  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                Offer_discount.objects.filter(
                    id=user_data["id"]).update(created_by=str(UserID))
                return Response({
                    "response_code": 201,
                    "response_message": _("Offer has been created."),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                # Blank Validation
                if serializer.errors.get('offer_name_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer name must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_description_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer description must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_code_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer code must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_minium_value_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer minium_value must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_start_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer start must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_end_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer end must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Time Validation
                elif serializer.errors.get('Invalid_Time'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("End time is less than Start Time")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Amount & % & up to value
                elif serializer.errors.get('Invalid_fields'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("You shuld enter Offer amount or (offer percentage and offer upto value)")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_amount_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer amount must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_amount_zero'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer amount must be greater than 0 (zero).")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Offer Percentage & Upto value
                elif serializer.errors.get('offer_percentage_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("YOffer percentage must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_upto_valueblank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer upto value must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_percentage_zero'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer percentage must be between o and 99.99.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_upto_value_zero'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer upto amount must be greater than 0 (zero).")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Offer Percentage & Upto value
                elif serializer.errors.get('No_Update'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("You could not update offer.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Update Offer 
****************
"""


class Update_Offer_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Offer_discount_encrypt_serializers

    def get_object(self, pk):
        try:
            return Offer_discount.objects.get(pk=pk)
        except Offer_discount.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"offer_name": "String", "offer_description": "String", "offer_code": "string", "offer_minium_value" :integer, "offer_start": "date time string ", "offer_end": "date time string ", "offer_percentage": float/decimal value, "offer_upto_value": integer,}'),)
    def patch(self, request, pk, format=None):
        try:
            """================================================"""

            User_ID = self.get_object(pk)

            # # """===================== Decode JWT  ====================="""
            token = self.request.headers["Authorization"]
            UserID = DecodeJWT(token)

            # """================================================"""

            serializer = self.serializer_class(User_ID, data=request.data,  partial=True,
                                               context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data
                Offer_discount.objects.filter(
                    id=pk).update(updated_by=str(UserID))
                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("Offer has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:
                # Blank Validation
                if serializer.errors.get('offer_name_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer name must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_description_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer description must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_code_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer code must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_minium_value_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer minium_value must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_start_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer start must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_end_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer end must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Time Validation
                elif serializer.errors.get('Invalid_Time'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("End time is less than Start Time")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Amount & % & up to value
                elif serializer.errors.get('Invalid_fields'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("You shuld enter Offer amount or (offer percentage and offer upto value)")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_amount_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer amount must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_amount_zero'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer amount must be greater than 0 (zero).")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Offer Percentage & Upto value
                elif serializer.errors.get('offer_percentage_blank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("YOffer percentage must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_upto_valueblank_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer upto value must not be empty.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_percentage_zero'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer percentage must be between o and 99.99.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('offer_upto_value_zero'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Offer upto amount must be greater than 0 (zero).")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Offer Percentage & Upto value
                elif serializer.errors.get('No_Update'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("You could not update offer.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"code": 400, "message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Offer   - Delete
****************
"""


class DeleteSoft_Offer_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Offer_discount_serializers

    queryset = Offer_discount.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return Offer_discount.objects.get(pk=pk)
        except Offer_discount.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"name": "string",}'),)
    def delete(self, request, pk, format=None):

        # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        id_ForDel = self.get_object(pk)

        if id_ForDel.is_active == True:

            id_ForDel.is_active = False

            id_ForDel.save()

            Offer_discount.objects.filter(id=pk).update(
                updated_by=str(UserID))

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Successfully Deleted")},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 400,
                    'responseMessage':  _("Already Is Deleted")},
                status=status.HTTP_400_BAD_REQUEST)


"""
****************
    Offer List - Single 
****************
"""


class Get_Offer_AdminViews(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Offer_discount_serializers

    def get_object(self, pk):
        try:
            return Offer_discount.objects.get(pk=pk)
        except Offer_discount.DoesNotExist:
            raise NotFound(
                detail={"code": 404, 'message': "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, pk, format=None):

        data_id = self.get_object(pk)

        if data_id.is_active == True or data_id.is_active == False:

            serializer = self.serializer_class(
                data_id,  context={"request": request})

            # 'responseData': encrypt_data(serializer.data)},

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(serializer.data)},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Banner List - deleted 
****************
"""


class List_deleted_Offer_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = banner_serializers

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Offer_discount.objects.filter(Q(is_active=False))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Offer List - Active 
****************
"""


class List_Active_Offer_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Offer_discount_serializers

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Offer_discount.objects.filter(Q(is_active=True) & Q(
            offer_end__gt=datetime.datetime.now()))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Offer List - Expired 
****************
"""


class List_Expired_Offer_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Offer_discount_serializers

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Offer_discount.objects.filter(Q(is_active=True) & Q(
            offer_end__lt=datetime.datetime.now()))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Offer List - Future 
****************
"""


class List_Future_Offer_AdminViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.IsAdminUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = Offer_discount_serializers

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"name": "string",}'),)
    def get(self, request, format=None):

        data = Offer_discount.objects.filter(Q(is_active=True) & Q(
            offer_start__gt=datetime.datetime.now()))

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
********************
    Search Offer
********************
"""


class Search_Offer_views(ListAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]
    queryset = Offer_discount.objects.filter(is_active=True).order_by("id")
    serializer_class = Offer_discount_serializers
    filter_backends = [SearchFilter]
    search_fields = ['offer_name',  "offer_description", "offer_code", ]
