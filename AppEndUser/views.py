"""
*********
Rest Framework
*********
"""

# Permission

from rest_framework import permissions
from AppEndUser.CustomPermission import OnlyEndUser

# Response
from rest_framework.response import Response

# Class - Generic
from rest_framework.generics import GenericAPIView

# Parser & Status
from rest_framework.parsers import MultiPartParser
from rest_framework import status

# Language Translation
from django.utils.translation import gettext_lazy as _

# Serializers
from rest_framework.serializers import Serializer

# Error handling
from rest_framework.exceptions import NotFound

# Json Web Token
from rest_framework_simplejwt.authentication import JWTAuthentication

# Twilio Settings
from twilio.rest import Client
from django.conf import settings
from twilio.base import exceptions
from twilio.base.exceptions import TwilioRestException, TwilioException

# For Redis
from django.core.cache.backends.base import DEFAULT_TIMEOUT
from django.core.cache import cache

# Error Loging
from AppAdmin.Error_Log import Error_Log

# JSON Renderer For Encrypt Decrypt
from rest_framework.renderers import JSONRenderer

# Encrypt Decrypt data
from AppAdmin.EncryptDecrypt import encrypt_data, decrypt_data, Json_decrypt_data, OrderDict_to_json, ChangeDateTimeinJson


# Q Object
from django.db.models import Q
from django.db.models import F, Sum, Avg

# Data Time
import datetime

# json
import json

# Swagger
from drf_yasg.utils import swagger_auto_schema

# AuthToken
from AppAdmin.AuthToken import DecodeToken

# Email for verification
from AppAdmin.EmailConfig import SendEmail
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
from django.template.loader import get_template

# Indian Post API for Getting details of Pincode
from AppAdmin.PincodeAPI import Indian_Post_Pincode

# Decode JWT
from AppAdmin.DecodeJWT import DecodeJWT

# Models - Admin
from AppAdmin.models import (
    User,
    Pincode_DB,
    BookingSlot,
    CLB_Review,
    Courier_Company_Review,
    PriceForCustomer,
    CourierCompany,
    Support_Ticket,
    Banner,
    Offer_discount,
)


# Admin Serializers
from AppAdmin.serializers import (

    CLB_Review_Serializers,
    Courier_Company_Review_Serializers,
    ListPriceForCustomer_Serializers,

)

# # models - EndUser
from AppEndUser.models import (
    Sender_Receiver_Address,
    User_Card_Details,
    End_User_Order,

)


# EndUse Serializer.
from AppEndUser.serializers import (
    # Login
    EndUserRegister_Login_Serializers,
    VerifyOTP_serializers,

    # Sender & Receiver
    Sender_Address_Serializers,
    Sender_Receiver_Address_Book_Serializers,

    # Booking Slot
    End_BookSlot_Serializers,

    # Pincode
    GetPincodeDetails_serializers,

    # CLB_Review - encrypt & Decrypt
    CLB_Review_for_enduser_Serializers,
    Courier_Company_Review_for_enduser_Serializers,

    # Support Ticket
    SupportTicket_Encrypt_Serializres,
    SupportTicket_Serializers,

    # Banner
    EndUser_banner_serializers,

    # Offer
    EndUser_Offer_discount_serializers,
    Check_Offer_Serializers,

    # Card
    CardDetails_Encrypt_Serializers,
    CardDetails_Serializers,


    # Order Details
    End_User_Order_Encrypt_Serializers,
    EndUser_Order_Serializers,
)

from django.core import serializers
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
********************
    End-Super Loing & Signup
********************
"""


class EndUserLogin_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = EndUserRegister_Login_Serializers
    # parser_classes = [MultiPartParser, ]

    @swagger_auto_schema(tags=["End User Login"], operation_description=("payload:", '{"country_code":"String","phone": "String"}'),)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid(raise_exception=False):
            decrypt_datas = Json_decrypt_data(request.data["data"])

            mobile = str(decrypt_datas["country_code"]+decrypt_datas["phone"])

            if User.objects.filter(phone=decrypt_datas["phone"]):
                try:
                    # Check In Memory
                    if cache.get("mobile"):

                        return Response(
                            {
                                "response_code": 400,
                                "response_message": f'You can try to send OTP after {cache.ttl("mobile")} seconds.'

                            }, status=status.HTTP_400_BAD_REQUEST
                        )
                    else:

                        # Send OTP
                        verify.verifications.create(to=mobile, channel='sms')

                        # Set Key & Value Pair in Memory for 2 Min
                        cache.set("mobile", mobile, 60 * 2)

                        return Response({
                            "response_code": 200,
                            "response_message": _("The OTP has been sent to registered phone number. "),
                            "response_data": encrypt_data(decrypt_datas)},
                            status=status.HTTP_200_OK)

                except TwilioException as e:
                    Error_Log(e)
                    return Response({
                        "response_code": 400,
                        "response_message": _(e.args[2])},
                        status=status.HTTP_400_BAD_REQUEST)
                except Exception as e:
                    Error_Log(e)
                    return Response({
                        "response_code": 400,
                        "response_message": _(e)},
                        status=status.HTTP_400_BAD_REQUEST)
        else:
            if serializer.errors.get('country_code'):
                return Response({
                    "response_code": 400,
                    "response_message": _("Country Code must be start with '+', and Numeric")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get('Phonedigit'):
                return Response({
                    "response_code": 400,
                    "response_message": _("Phone number must be numeric")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get('Delete_User'):
                return Response({
                    "response_code": 400,
                    "response_message": _("User is Deleted")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get('phone_length'):
                return Response({
                    "response_code": 400,
                    "response_message": _("Please enter phone number between 10 to 20 length'")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get('End_User'):
                return Response({
                    "response_code": 400,
                    "response_message": _("Only End user can Login. ")},
                    status=status.HTTP_400_BAD_REQUEST)

            elif serializer.errors.get('register_otp'):
                return Response({
                    "response_code": 201,
                    "response_message": _("User is successfully registered, The OTP has been sent to registered phone number."),
                    "response_data": request.data["data"]
                },
                    status=status.HTTP_201_CREATED)

            elif serializer.errors.get('ErrorMessage'):
                return Response({
                    "response_code": 400,
                    "response_message": _("Twilio Error")},
                    status=status.HTTP_400_BAD_REQUEST)

        return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)


"""
********************
    # Verify OTP Hello
********************
"""


class VerifyOTP_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = VerifyOTP_serializers

    @swagger_auto_schema(tags=["End User Login"], operation_description=("Payload: ", '{"country_code":"String","phone" : "String","otpCode": "String"}'),)
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=False):
            decrypt_datas = Json_decrypt_data(request.data["data"])

            try:
                result = verify.verification_checks.create(
                    to=str(decrypt_datas["country_code"]+decrypt_datas["phone"]), code=decrypt_datas["otpCode"])

                if result.status == "approved":
                    user1 = User.objects.get(phone=decrypt_datas["phone"]).id

                    user = User.objects.get(id=user1)

                    return Response({
                        "response_code": 200,
                        "response_message": _("Login Successfully."),
                        "response_data": encrypt_data({
                            "user_id": user1,
                            "user_type": "EndUser",
                            "country_code": decrypt_datas["country_code"],
                            "phone": decrypt_datas["phone"],
                            "token": {'refresh': user.tokens()['refresh'],
                                      'access': user.tokens()['access']}
                        }),
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
**************************************************************************
                    Sender & Receiver Address
**************************************************************************
"""

"""
***********
    Add - Sender & Receiver Address
***********
"""


class Sender_Address_Create_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]

    serializer_class = Sender_Address_Serializers

    @swagger_auto_schema(tags=["Sender & Receiver Address"], operation_description=("Payload:", '{"user_id": "String","first_name": "String","last_name": "String","country_code": "String","phone": "String","address": "String","landmarks": "String","city": "String","pincode": "String","country": "String","latitude": "String","longitude": "String",}'),)
    def post(self, request, *args, **kwargs):
        try:

            serializer = self.serializer_class(
                data=request.data, context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()

                """===================== Authoratation  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)
                Sender_Receiver_Address.objects.filter(id=serializer.data["id"]).update(
                    created_by=str(UserID))

                """=========================================="""

                # Sender_data = Sender_Receiver_Address.objects.filter(
                #     id=serializer.data["id"]).values()
                # Sender_data = [i for i in Sender_data]
                Sender_data = ChangeDateTimeinJson(Sender_Receiver_Address.objects.filter(
                    id=serializer.data["id"]).values())

                """===================== Email ====================="""

                return Response({
                    "response_code": 201,
                    "response_message": _("Sender Address has been created."),
                    "response_data": encrypt_data(Sender_data)},
                    status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('UserId'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exist. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('First_Last_Name'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("First Name and Last Name must be alphabet.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Country_Code'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Country must be start with '+', and Numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Phonedigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Validation
                elif serializer.errors.get('Phonelength'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone must be bewtween 8  to 12 Characters")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('City'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("City  nad Country must be Alphbet")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


class Receiver_Address_Create_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]

    serializer_class = Sender_Address_Serializers

    @swagger_auto_schema(tags=["Sender & Receiver Address"], operation_description=("Payload :", '{"user_id": "String","address_type": "String","first_name": "String","last_name": "String","country_code": "String","phone": "String","address": "String","landmarks": "String","city": "String","pincode": "String","country": "String","latitude": "String","longitude": "String",}'),)
    def post(self, request, *args, **kwargs):
        try:

            serializer = self.serializer_class(
                data=request.data, context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()

                """===================== Authoratation  ====================="""
                token = self.request.headers["Authorization"]
                UserID = DecodeJWT(token)
                Sender_Receiver_Address.objects.filter(id=serializer.data["id"]).update(
                    created_by=str(UserID))

                """=========================================="""

                # Sender_data = Sender_Receiver_Address.objects.filter(
                #     id=serializer.data["id"]).values()
                Receiver_data = ChangeDateTimeinJson(Sender_Receiver_Address.objects.filter(
                    id=serializer.data["id"]).values())

                return Response({
                    "response_code": 201,
                    "response_message": _("Receiver Address has been created."),
                    "response_data": encrypt_data(Receiver_data)},
                    status=status.HTTP_201_CREATED)
            else:

                if serializer.errors.get('UserId'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exist. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('First_Last_Name'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("First Name and Last Name must be alphabet.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Country_Code'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Country must be start with '+', and Numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Phonedigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Validation
                elif serializer.errors.get('Phonelength'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone must be bewtween 8  to 12 Characters")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('City'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("City  nad Country must be Alphbet")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***********
    List Sender & Receiver Address
***********
"""


class List_Sender_Receiver_Address_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]

    serializer_class = Sender_Receiver_Address_Book_Serializers

    @swagger_auto_schema(tags=["Sender & Receiver Address"], operation_description=("List Data ",))
    def get(self, request, format=None):
        """===================== Authoratation  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        Address_Data = Sender_Receiver_Address.objects.filter(
            user_idSRAdd=UserID, is_active=True).order_by("id")

        serializer = self.serializer_class(
            Address_Data, many=True, context={"request": request})

        return Response(
            {"response_code": 200,
             "response_message": _("Success"),
             'data': encrypt_data(OrderDict_to_json(serializer.data))
             },
            status=status.HTTP_200_OK)


"""
***********
    Soft Delete Sender & Receiver Address
***********
"""


class Delete_Soft_Address_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]

    serializer_class = Sender_Receiver_Address_Book_Serializers

    queryset = Sender_Receiver_Address.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return Sender_Receiver_Address.objects.get(pk=pk)
        except Sender_Receiver_Address.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Sender & Receiver Address"], operation_description=("List Data ",))
    def delete(self, request, pk, format=None):

        # # """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        # """================================================"""
        Address_for_del = self.get_object(pk)

        if Address_for_del.is_active == True:

            Address_for_del.is_active = False

            Address_for_del.save()

            Sender_Receiver_Address.objects.filter(id=pk).update(
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
***********
    Update Sender & Receiver Address
***********
"""


class Update_Receiver_Address_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]

    serializer_class = Sender_Address_Serializers

    def get_object(self, pk):
        try:
            return Sender_Receiver_Address.objects.get(pk=pk)
        except Sender_Receiver_Address.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Sender & Receiver Address"], operation_description=("Payload :", '{"user_idSRAdd": "String","first_name": "String","last_name": "String","country_code": "String","phone": "String","address": "String","landmarks": "String","city": "String","pincode": "String","country": "String","latitude": "String","longitude": "String",}'),)
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
                Sender_Receiver_Address.objects.filter(
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

                if serializer.errors.get('UserId'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exist. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('First_Last_Name'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("First Name and Last Name must be alphabet.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Country_Code'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Country must be start with '+', and Numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Phonedigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Validation
                elif serializer.errors.get('Phonelength'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone must be bewtween 8  to 12 Characters")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('City'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("City  nad Country must be Alphbet")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***********
    Get Single address
***********
"""


class Get_Singal_AddressBook_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [OnlyEndUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = Sender_Receiver_Address_Book_Serializers

    def get_object(self, pk):
        try:
            return Sender_Receiver_Address.objects.get(pk=pk)
        except Sender_Receiver_Address.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Sender & Receiver Address"], operation_description=("List Data ",))
    def get(self, request, pk, format=None):

        AddressBook_id = self.get_object(pk)

        if AddressBook_id.is_active == True:

            serializer = self.serializer_class(
                AddressBook_id,  context={"request": request})

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
**************************************************************************
                            Pincode
**************************************************************************
"""


"""
*****************
  Check CLB PickUp Pincode
*****************
"""


class Check_CLB_PickUp_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = GetPincodeDetails_serializers

    @ swagger_auto_schema(tags=["Pincode"], operation_description="Get Pincode Details")
    def get(self, request, pincode, format=None):
        try:
            PincodeList = Pincode_DB.objects.filter(Q(pincode=pincode) & Q(is_clb_pickup=True) &
                                                    Q(is_active=True))
            if len(PincodeList) > 0:

                return Response(
                    {"response_code": 200,
                     'response_message': _("Available Pickup"), },
                    status=status.HTTP_200_OK)

            else:
                return Response(
                    {"response_code": 400,
                     'response_message': _("unavailable Pickup service"), },
                    status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
*****************
  Check Delivery Pincode
*****************
"""


class Check_Delivery_pincode_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = GetPincodeDetails_serializers

    @ swagger_auto_schema(tags=["Pincode"], operation_description="Get Pincode Details")
    def get(self, request, pincode, format=None):
        try:
            PincodeList = Pincode_DB.objects.filter(Q(pincode=pincode) & Q(is_delivery=True) &
                                                    Q(is_active=True))
            if len(PincodeList) > 0:

                return Response(
                    {"response_code": 200,
                     'response_message': _("Available Delivery"), },
                    status=status.HTTP_200_OK)

            else:
                return Response(
                    {"response_code": 400,
                     'response_message': _("unavailable Delivery"), },
                    status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
*****************
    PickUp Pincode
*****************
"""


# class Get_Specific_Pickup_Pincode_Views(GenericAPIView):
#     authentication_classes = [JWTAuthentication]
#     permission_classes = [permissions.AllowAny]

#     serializer_class = GetPincodeDetails_serializers

#     @ swagger_auto_schema(tags=["Pincode"], operation_description="Get Pincode Details")
#     def get(self, request, pincode, format=None):
#         try:
#             PincodeList = Pincode_DB.objects.filter(Q(pincode=pincode) & Q(is_pickup=True) &
#                                                     Q(is_active=True)).order_by("id")
#             if len(PincodeList) > 0:
#                 serializer = self.serializer_class(PincodeList, many=True,
#                                                    context={"request": request})

#                 serializer.data[0]['Area_Name'] = Indian_Post_Pincode(
#                     int(pincode))

#                 if cache.get(str(pincode)):
#                     return Response(
#                         {"response_code": 200,
#                             'response_message': _("Success"),
#                             'response_data': cache.get(str(pincode))},
#                         status=status.HTTP_200_OK)
#                 else:
#                     # Set Key & Value Pair in Memory for seconds * minutes
#                     cache.set(str(pincode), serializer.data, 60 * 2)
#                     return Response(
#                         {"response_code": 200,
#                             'response_message': _("Success"),
#                             'response_data': serializer.data},
#                         status=status.HTTP_200_OK)
#             else:
#                 return Response(
#                     {"response_code": 404,
#                      'response_message': _("Data Not found"), },
#                     status=status.HTTP_404_NOT_FOUND)
#         except Exception as e:
#             Error_Log(e)
#             return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
*****************
    Delivery Pincode
*****************
"""


class Get_Specific_Delivery_Pincode_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = GetPincodeDetails_serializers

    @ swagger_auto_schema(tags=["Pincode"], operation_description="Get Pincode Details")
    def get(self, request, pincode, format=None):
        try:
            PincodeList = Pincode_DB.objects.filter(Q(pincode=pincode) & Q(is_delivery=True) &
                                                    Q(is_active=True)).order_by("id")
            if len(PincodeList) > 0:
                serializer = self.serializer_class(PincodeList, many=True,
                                                   context={"request": request})

                serializer.data[0]['Area_Name'] = Indian_Post_Pincode(
                    int(pincode))

                if cache.get(str(pincode)):
                    return Response(
                        {"response_code": 200,
                            'response_message': _("Success"),
                            'response_data': cache.get(str(pincode))},
                        status=status.HTTP_200_OK)
                else:
                    # Set Key & Value Pair in Memory for seconds * minutes
                    cache.set(str(pincode), serializer.data, 60 * 2)
                    return Response(
                        {"response_code": 200,
                            'response_message': _("Success"),
                            'response_data': serializer.data},
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
**************************************************************************
                            Booking Slot
**************************************************************************
"""


class End_Booking_Slot_view(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = End_BookSlot_Serializers

    @ swagger_auto_schema(tags=["Booking Slot"], operation_description="Get list of Booking Slot")
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            if serializer.is_valid(raise_exception=False):

                date = serializer.validated_data['date']

                if date < datetime.datetime.now().date():
                    return Response({"response_code": 400, "response_message": "Please choose current or future date"}, status=status.HTTP_400_BAD_REQUEST)

                # Empty List
                Booked_data = []
                available_data = []

                current_time = datetime.datetime.now().time()

                for i in BookingSlot.objects.filter(
                        is_active=True).values("allow_time_after_start_time"):
                    if current_time > i["allow_time_after_start_time"]:
                        Booked_data.append(BookingSlot.objects.filter(
                            allow_time_after_start_time=i["allow_time_after_start_time"], is_active=True).values("id", "start_time", "end_time"))
                    elif current_time < i["allow_time_after_start_time"]:
                        available_data.append(BookingSlot.objects.filter(
                            allow_time_after_start_time=i["allow_time_after_start_time"], is_active=True).values("id", "start_time", "end_time"))

                return Response(
                    {"response_code": 200,
                     "response_message": _("Success"),
                     'data': encrypt_data({
                         "Booked": [Booked_data[i][0]
                                    for i in range(len(Booked_data))], "Available": [available_data[i][0]
                                                                                     for i in range(len(available_data))]})},
                    status=status.HTTP_200_OK)

            else:
                if serializer.errors["date"]:
                    return Response({"response_code": 400, "response_message": "Date has wrong format. Use one of these formats instead: YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************************************************************************************************************************************************
                                                            Review CLB & Courier Company
****************************************************************************************************************************************************
"""


"""
*****************
    Post CLB Review
*****************
"""


class POst_CLB_Review_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = CLB_Review_for_enduser_Serializers

    @ swagger_auto_schema(tags=["CLB Review"], operation_description=("Payload :", '{"review_answer": "Integer","comment": "String",}'))
    def post(self, request, *args, **kwargs):
        try:

            serializer = self.serializer_class(
                data=request.data, context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()

                """===================== Create By & Update On ====================="""

                if "Authorization" in self.request.headers:

                    token = self.request.headers["Authorization"]
                    UserID = DecodeJWT(token)
                    CLB_Review.objects.filter(
                        id=serializer.data['id']).update(Review_by=str(UserID))

                Review_data = ChangeDateTimeinJson([i for i in CLB_Review.objects.filter(
                    id=serializer.data["id"]).values()])

                return Response({
                    "response_code": 201,
                    "response_message": _("Review is posted."),
                    "response_data": encrypt_data(Review_data)},
                    status=status.HTTP_201_CREATED)

            else:
                if serializer.errors.get('Review'):
                    return Response({"response_code": 400, "response_message": "Review Rating between 0 to 5"}, status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
*****************
    List CLB Review
*****************
"""


class List_CLB_Review_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]
    serializer_class = CLB_Review_Serializers

    @ swagger_auto_schema(tags=["CLB Review"], operation_description="CLB Review list",)
    def get(self, request, format=None):
        Review_Data = CLB_Review.objects.all().order_by("id")

        serializer = self.serializer_class(
            Review_Data, many=True, context={"request": request})

        return Response(
            {"response_code": 200,
             "response_message": _("Success"),
             'data': encrypt_data(OrderDict_to_json(serializer.data))},
            status=status.HTTP_200_OK)


"""
*****************
    Post Courier Company Review
*****************
"""


class Post_Courier_Company_Review_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = Courier_Company_Review_for_enduser_Serializers

    @ swagger_auto_schema(tags=["CLB Review"], operation_description=("Payload :", '{"CC_id":integer , "review_answer": "Integer","comment": "String",}'))
    def post(self, request, *args, **kwargs):
        try:

            serializer = self.serializer_class(
                data=request.data, context={"request": request})

            if serializer.is_valid(raise_exception=False):
                serializer.save()

                """===================== Create By & Update On ====================="""

                if "Authorization" in self.request.headers:

                    token = self.request.headers["Authorization"]
                    UserID = DecodeJWT(token)
                    Courier_Company_Review.objects.filter(
                        id=serializer.data['id']).update(Review_User=str(UserID))

                Review_data = ChangeDateTimeinJson([i for i in Courier_Company_Review.objects.filter(
                    id=serializer.data["id"]).values()])

                return Response({
                    "response_code": 201,
                    "response_message": _("Review is posted."),
                    "response_data": encrypt_data(Review_data)},
                    status=status.HTTP_201_CREATED)

            else:
                if serializer.errors.get('No_Courier_Company'):
                    return Response({"response_code": 400, "response_message": "Courier Company Does not exists."}, status=status.HTTP_400_BAD_REQUEST)
                elif serializer.errors.get('Review'):
                    return Response({"response_code": 400, "response_message": "Review Rating between 0 to 5"}, status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
*****************
    List Courier Company Review
*****************
"""


class List_Courier_Company_Review_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]
    serializer_class = Courier_Company_Review_Serializers

    @ swagger_auto_schema(tags=["CLB Review"], operation_description="CLB Review list",)
    def get(self, request, format=None):
        Review_Data = Courier_Company_Review.objects.all().order_by("id")

        serializer = self.serializer_class(
            Review_Data, many=True, context={"request": request})

        return Response(
            {"response_code": 200,
             "response_message": _("Success"),
             'data': encrypt_data(OrderDict_to_json(serializer.data))},
            status=status.HTTP_200_OK)


"""
****************************************************************************************************************************************************
                                                            Compare Price
****************************************************************************************************************************************************
"""


"""
*****************
    Compare Price
*****************
"""


class Compare_Price_View(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]
    serializer_class = ListPriceForCustomer_Serializers

    @ swagger_auto_schema(tags=["Compare Price"], operation_description="Compare Price  ",)
    def get(self, request, ShipmentType, Weight, FromPincode, ToPincode, format=None):

        try:
            if not Pincode_DB.objects.filter(pincode=str(FromPincode)
                                             ) or not Pincode_DB.objects.filter(pincode=str(ToPincode)):
                return Response({"response_code": 404, "response_message": _("Invalid Pincode"), }, status=status.HTTP_404_NOT_FOUND)

            else:

                # Local
                if Pincode_DB.objects.filter(
                        pincode=str(FromPincode)).values("City").distinct()[0]['City'] == Pincode_DB.objects.filter(
                        pincode=str(ToPincode)).values("City").distinct()[0]['City']:

                    # Documents
                    if ShipmentType == "Documents":
                        Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Documents", PriceCCId__Weight_From__lte=Weight, PriceCCId__Weight_To__gte=Weight).values(
                            "id", "name", "logo", "PriceCCId__ShipmentType", "PriceCCId__ServiceType", "PriceCCId__Local").annotate(
                            Review=Avg("ReviewCCId__review_answer"))

                    # Parcel
                    elif ShipmentType == "Parcel":
                        # Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Parcel", PriceCCId__Weight_From__lte=Weight, PriceCCId__Weight_To__gte=Weight).values(

                        Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Parcel", ).values(
                            "id", "name", "logo", "PriceCCId__TravelBy", "PriceCCId__ShipmentType", "PriceCCId__ServiceType", "PriceCCId__Local").annotate(
                            Review=Avg("ReviewCCId__review_answer"))

                        for i in Data:
                            i["PriceCCId__Local"] = i["PriceCCId__Local"] * \
                                int(float(Weight / 1000) + 1)

                    else:
                        return Response({"response_code": 404, "response_message": _("Invalid Shipment Type"), }, status=status.HTTP_404_NOT_FOUND)

                # State
                elif Pincode_DB.objects.filter(
                        pincode=str(FromPincode)).values("State").distinct()[0]['State'] == Pincode_DB.objects.filter(
                        pincode=str(ToPincode)).values("State").distinct()[0]['State']:

                    # Documents
                    if ShipmentType == "Documents":
                        Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Documents", PriceCCId__Weight_From__lte=Weight, PriceCCId__Weight_To__gte=Weight).values(
                            "id", "name", "logo", "PriceCCId__ShipmentType", "PriceCCId__ServiceType", "PriceCCId__State").annotate(
                            Review=Avg("ReviewCCId__review_answer"))

                    # Parcel
                    elif ShipmentType == "Parcel":
                        # Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Parcel", PriceCCId__Weight_From__lte=Weight, PriceCCId__Weight_To__gte=Weight).values(
                        Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Parcel").values(
                            "id", "name", "logo", "PriceCCId__TravelBy", "PriceCCId__ShipmentType", "PriceCCId__ServiceType", "PriceCCId__State").annotate(
                            Review=Avg("ReviewCCId__review_answer"))

                        for i in Data:
                            i["PriceCCId__State"] = i["PriceCCId__State"] * \
                                int(float(Weight / 1000) + 1)

                    # Error
                    else:
                        return Response({"response_code": 404, "response_message": _("Invalid Shipment Type"), }, status=status.HTTP_404_NOT_FOUND)

                # Country
                elif Pincode_DB.objects.filter(
                        pincode=str(FromPincode)).values("Country").distinct()[0]['Country'] == Pincode_DB.objects.filter(
                        pincode=str(ToPincode)).values("Country").distinct()[0]['Country']:

                    # Documents
                    if ShipmentType == "Documents":
                        Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Documents", PriceCCId__Weight_From__lte=Weight, PriceCCId__Weight_To__gte=Weight).values(
                            "id", "name", "logo", "PriceCCId__ShipmentType", "PriceCCId__ServiceType", "PriceCCId__RestOfIndia").annotate(
                            Review=Avg("ReviewCCId__review_answer"))

                    # Parcel
                    elif ShipmentType == "Parcel":
                        # Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Parcel", PriceCCId__Weight_From__lte=Weight, PriceCCId__Weight_To__gte=Weight).values(

                        Data = CourierCompany.objects.filter(PriceCCId__ShipmentType="Parcel",).values(
                            "id", "name", "logo", "PriceCCId__TravelBy", "PriceCCId__ShipmentType", "PriceCCId__ServiceType", "PriceCCId__RestOfIndia").annotate(
                            Review=Avg("ReviewCCId__review_answer"))

                        for i in Data:
                            i["PriceCCId__RestOfIndia"] = i["PriceCCId__RestOfIndia"] * \
                                int(float(Weight / 1000) + 1)

                    # Error
                    else:
                        return Response({"response_code": 404, "response_message": _("Invalid Shipment Type"), }, status=status.HTTP_404_NOT_FOUND)

                return Response(
                    {"response_code": 200,
                     "response_message": _("Success"),
                     'data': encrypt_data(OrderDict_to_json(Data))},
                    #  'data': Data},
                    status=status.HTTP_200_OK)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************************************************************************************************************************************************
                                                            Support Ticket
****************************************************************************************************************************************************
"""


"""
*****************
    Create Support Ticket
*****************
"""


class Create_Support_Ticket_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    # permission_classes = [OnlyEndUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = SupportTicket_Encrypt_Serializres
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Ticket - EndUser"], operation_description=("Payload:", '{"country_code": "string", "requester_phone": "string","requester_email": "string","issue_Cate_id": int,"subject": "string","description": "string","order_id": "string"}'),)
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(
                data=request.data, context={"request": request})
            if serializer.is_valid(raise_exception=False):
                serializer.save()
                user_data = serializer.data

                """===================== Decode JWT  ====================="""
                # token = self.request.headers["Authorization"]
                # UserID = DecodeJWT(token)

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                """===================== Insert end user id  ====================="""

                EndUser_id = User.objects.get(id=100)

                Support_Ticket.objects.filter(
                    id=user_data["id"]).update(client_User_Id=User.objects.get(id=100), created_by=str(EndUser_id))

                # Email to Admin
                SendEmail.send_email({
                    "email_body": get_template('forgetPassword.html').render({
                        'CustomerName': EndUser_id.first_name,
                        'ticketNumber': Support_Ticket.objects.get(id=user_data["id"]).ticket_no,
                        'ticketDate': Support_Ticket.objects.get(id=user_data["id"]).ticket_no
                    }),
                    "to_email": "ks4223839@gmail.com",
                    "email_subject": "Ticket Number",
                })
                # Email to User
                SendEmail.send_email({
                    "email_body": get_template('forgetPassword.html').render({
                        'CustomerName': EndUser_id.first_name,
                        'ticketNumber': Support_Ticket.objects.get(id=user_data["id"]).ticket_no,
                        'ticketDate': Support_Ticket.objects.get(id=user_data["id"]).ticket_no
                    }),
                    "to_email": Support_Ticket.objects.get(id=user_data["id"]).ticket_no.requester_email,
                    "email_subject": "Ticket Number",
                })

                return Response({
                    "response_code": 201,
                    "response_message": _("Your Ticket has been generated."),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('No_Issuse_Category'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Issue Category Does not exists.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('email_validation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Please, Enter the correct E-Mail.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Country_Code'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Country must be start with '+', and Numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Phonedigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Phonelength'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Phone must be bewtween 8  to 12 Characters")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
*****************
    Open - List  Support Ticket
*****************
"""


class List_Open_Support_Ticket_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = SupportTicket_Serializers

    @ swagger_auto_schema(tags=["Ticket - EndUser"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        data = Support_Ticket.objects.filter(
            Q(is_active=True) & Q(status="Open") & Q(status="Open") & Q(client_User_Id=User.objects.get(id=UserID)) & Q(is_closed=False))

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


class List_In_Progress_Support_Ticket_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = SupportTicket_Serializers

    @ swagger_auto_schema(tags=["Ticket - EndUser"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        data = Support_Ticket.objects.filter(
            Q(is_active=True) & Q(status="In_Progress") & Q(client_User_Id=User.objects.get(id=UserID)) & Q(is_closed=False))

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


class List_Closed_Support_Ticket_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = SupportTicket_Serializers

    @ swagger_auto_schema(tags=["Ticket - EndUser"], operation_description="Get Admin User Details",)
    def get(self, request, format=None):
        """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        data = Support_Ticket.objects.filter(
            Q(is_active=True) & Q(status="Closed") & Q(client_User_Id=User.objects.get(id=UserID)) & Q(is_closed=True))

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
    Support - List - Single
****************
"""


class Get_SupportTicket_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = SupportTicket_Serializers

    def get_object(self, pk):
        try:
            return Support_Ticket.objects.get(pk=pk)
        except Support_Ticket.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @ swagger_auto_schema(tags=["Ticket - EndUser"], operation_description="Get Admin User Details",)
    def get(self, request, pk, format=None):
        """===================== Decode JWT  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        data_id = self.get_object(pk)

        if data_id.is_active == True and data_id.client_User_Id == User.objects.get(id=UserID):

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
****************************************************************************************************************************************************
                                                            Banner
****************************************************************************************************************************************************
"""

"""
****************
    Banner List - Active
****************
"""


class List_Active_Banner_EndUserViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [permissions.AllowAny]

    serializer_class = EndUser_banner_serializers

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
****************************************************************************************************************************************************
                                                            Offer
****************************************************************************************************************************************************
"""


"""
****************
    Offer List - Active
****************
"""


class List_Active_Offer_EndUserViews(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = EndUser_Offer_discount_serializers

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
    Offer List - Single
****************
"""


class Get_Offer_EndUserViews(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = EndUser_Offer_discount_serializers

    def get_object(self, pk):
        try:
            return Offer_discount.objects.get(pk=pk)
        except Offer_discount.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["Offer"], operation_description=("Payload:", '{"name": "string",}'),)
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
                #  'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************
    Check Offer
****************
"""


class PromoCode_Get_View(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [OnlyEndUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = Check_Offer_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["Offer"], operation_description=("Parameters:", '{"coupon_code": "String", "Purchase_Amount": intger}'),)
    def get(self, request,  coupon_code, Purchase_Amount, *args, **kwargs):
        try:
            OfferData = Offer_discount.objects.get(offer_code=coupon_code)

            if Offer_discount.objects.filter(Q(offer_code=coupon_code) & Q(offer_end__lt=datetime.datetime.now())).exists():
                return Response(
                    {"response_code": 400,
                     "response_message": _("The promo has expired"), },
                    status=status.HTTP_400_BAD_REQUEST)

            elif Offer_discount.objects.filter(Q(offer_code=coupon_code) & Q(offer_minium_value__gt=float(Purchase_Amount))).exists():
                return Response(
                    {"response_code": 400,
                     "response_message": _(f"You should purchase more ₹ {int(OfferData.offer_minium_value) - float(Purchase_Amount)} amount"), },
                    status=status.HTTP_400_BAD_REQUEST)

            else:

                if OfferData.offer_amount and not OfferData.offer_percentage and not OfferData.offer_upto_value:
                    return Response(
                        {"response_code": 200,
                         "response_message": "Success",
                         "response_data": encrypt_data({
                             "Coupon_code": str(coupon_code),
                             "Purchase_Amount": float(Purchase_Amount),
                             "Discount_amount": OfferData.offer_amount,
                             "total": float(Purchase_Amount) - int(OfferData.offer_amount)
                         })},
                        status=status.HTTP_200_OK)

                elif not OfferData.offer_amount and OfferData.offer_percentage and OfferData.offer_upto_value:

                    return Response(
                        {"response_code": 200,
                         "response_message": "Success",
                         "response_data": encrypt_data({
                             "Coupon_code": str(coupon_code),
                             "Purchase_Amount": float(Purchase_Amount),
                             "Percentage": float(OfferData.offer_percentage),
                             "Upto_dicount_value": float(OfferData.offer_upto_value),
                             "discount_amount": ((float(Purchase_Amount) * float(OfferData.offer_percentage)) / 100) if ((float(Purchase_Amount) * float(OfferData.offer_percentage) / 100)) < float(OfferData.offer_upto_value) else float(OfferData.offer_upto_value),
                             "total": float(Purchase_Amount) - ((float(Purchase_Amount) * float(OfferData.offer_percentage)) / 100) if ((float(Purchase_Amount) * float(OfferData.offer_percentage) / 100)) < float(OfferData.offer_upto_value) else (float(Purchase_Amount) - float(OfferData.offer_upto_value))
                         })},
                        status=status.HTTP_200_OK)

        except Offer_discount.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Invalid Promo Code"}, code=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
****************************************************************************************************************************************************
                                                            Card Details
****************************************************************************************************************************************************
"""


"""
*****************
    Create Card Details
*****************
"""


class Create_Card_Details_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = CardDetails_Encrypt_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["EndUser Card Details"], operation_description=("Payload:", '{"UserCard_id": Intger, "Owner_name": "String","card_number": "String","exp_date (Only Number)" : "string(mm/yy)"}'),)
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

                """===================== Insert end user id  ====================="""

                # EndUser_id = User.objects.get(id=100)
                EndUser_id = User.objects.get(id=UserID)

                User_Card_Details.objects.filter(
                    id=user_data["id"]).update(created_by=str(EndUser_id))

                return Response({
                    "response_code": 201,
                    "response_message": _("Card details has been saved."),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                if serializer.errors.get('No_User_id'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User id must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('UserId'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exist. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('No_owener_name'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Owner name must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Ownervalidation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Only allow Alphbet and white space.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('card_empy'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card number must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('card_length'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card Length must be bewtween 8  to 20 Characters")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('CardDigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Card_Date'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card Expire Date must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('CardExp'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Expire Date must be length of 5. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('ExpireValidation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Expire date must be entered 'mm/yy' .")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***********
    Update Card Details
***********
"""


class Update_Card_Details_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [OnlyEndUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = CardDetails_Encrypt_Serializers

    def get_object(self, pk):
        try:
            return User_Card_Details.objects.get(pk=pk)
        except User_Card_Details.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["EndUser Card Details"], operation_description=("Payload:", '{"UserCard_id": Intger, "Owner_name": "String","card_number": "String","exp_date (Only Number)" : "string(mm/yy)"}'),)
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
                User_Card_Details.objects.filter(
                    id=pk).update(updated_by=str(UserID))

                """===================== Encrypt & Decrypt Data ====================="""

                # Decrypt Data
                Json_data = Json_decrypt_data(request.data["data"])
                response_data = Json_data.copy()
                response_data["id"] = user_data["id"]

                return Response({
                    "response_code": 200,
                    "response_message": _("Card Details has been updated."),
                    "response_data": encrypt_data(response_data), },
                    status=status.HTTP_200_OK)

            else:

                if serializer.errors.get('No_User_id'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User id must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('UserId'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exist. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('No_owener_name'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Owner name must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Ownervalidation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Only allow Alphbet and white space.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('card_empy'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card number must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('card_length'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card Length must be bewtween 8  to 20 Characters")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('CardDigit'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card number must be numeric")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Card_Date'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Card Expire Date must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('CardExp'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Expire Date must be length of 5. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('ExpireValidation'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Expire date must be entered 'mm/yy' .")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
***********
    List Card
***********
"""


class List_Card_Details_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CardDetails_Serializers

    @swagger_auto_schema(tags=["EndUser Card Details"], operation_description=("List Data ",))
    def get(self, request, format=None):
        """===================== Authoratation  ====================="""
        token = self.request.headers["Authorization"]
        UserID = DecodeJWT(token)

        Address_Data = User_Card_Details.objects.filter(
            UserCard_id=UserID, is_active=True).order_by("id")

        serializer = self.serializer_class(
            Address_Data, many=True, context={"request": request})

        return Response(
            {"response_code": 200,
             "response_message": _("Success"),
             'data': encrypt_data(OrderDict_to_json(serializer.data))
             },
            status=status.HTTP_200_OK)


"""
***********
    Hard Delete Card Details
***********
"""


class Delete_Hard_Card_Details_views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CardDetails_Serializers

    queryset = User_Card_Details.objects.filter(is_active=True)

    def get_object(self, pk):
        try:
            return User_Card_Details.objects.get(pk=pk)
        except User_Card_Details.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["EndUser Card Details"], operation_description=("List Data ",))
    def delete(self, request, pk, format=None):
        Card_ID = self.get_object(pk)
        Card_ID.delete()
        return Response(
            {"responseCode": 200,
             'responseMessage': _("Successfully Deleted")},
            status=status.HTTP_200_OK)


"""
***********
    Get Single Card
***********
"""


class Get_Singal_Card_Details_views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = CardDetails_Serializers

    def get_object(self, pk):
        try:
            return User_Card_Details.objects.get(pk=pk)
        except User_Card_Details.DoesNotExist:
            raise NotFound(
                detail={"response_code": 404, "response_message": "Data Not Found"}, code=status.HTTP_404_NOT_FOUND)

    @swagger_auto_schema(tags=["EndUser Card Details"], operation_description=("List Data ",))
    def get(self, request, pk, format=None):

        AddressBook_id = self.get_object(pk)

        if AddressBook_id.is_active == True:

            serializer = self.serializer_class(
                AddressBook_id,  context={"request": request})

            return Response(
                {"responseCode": 200,
                    'responseMessage': _("Success"),
                    'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                # 'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)


"""
****************************************************************************************************************************************************
                                                            End User Order Details 
****************************************************************************************************************************************************
"""


"""
*****************
    Create Order Details 
*****************
"""


class Create_EndUser_Order_Views(GenericAPIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [OnlyEndUser]
    # permission_classes = [permissions.AllowAny]

    serializer_class = End_User_Order_Encrypt_Serializers
    # renderer_classes = (UserRenderer)

    @swagger_auto_schema(tags=["EndUser Order"], operation_description=("Payload:", '{"UserCard_id": Intger, "Owner_name": "String","card_number": "String","exp_date (Only Number)" : "string(mm/yy)"}'),)
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

                """===================== Insert end user id  ====================="""

                # EndUser_id = User.objects.get(id=100)
                EndUser_id = User.objects.get(id=UserID)

                End_User_Order.objects.filter(
                    id=user_data["id"]).update(created_by=str(EndUser_id))

                return Response({
                    "response_code": 201,
                    "response_message": _("order has been generated."),
                    "response_data": encrypt_data(response_data)},
                    status=status.HTTP_201_CREATED)
                # return Response(user_data, status=status.HTTP_201_CREATED)
            else:
                # No Data
                if serializer.errors.get('no_Courier'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Courier compnay must be enterd.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_user'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User id must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_Sender'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Sender id must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_receiver'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Receiver id must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_origin'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Orgin  must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_destination'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Destination  must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_service'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Service type  must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_shipment'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Shipment Type  must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_Travel'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("No Travel type  must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_content'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Content must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_value'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("value must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_weight'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Weight must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_taxeble'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Taxeble amount must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_sgst'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("SGST must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_cgst'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("CSGT must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_pickup'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("No Pickup must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_totalcharge'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Total Charge must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Exist
                elif serializer.errors.get('Exist_Courier'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Courier does not exists.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Exist_User'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("User does not exist. ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Exist_Sender_address'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Sender address does not exists.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Exist_Receiver_address'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Receiver address does not exists.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Not in list
                elif serializer.errors.get('Check_Service_type'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Service Type must be entered Standard or Priority")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Check_Shipment_type'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Shipment Type must be entered Documents or Parcel ")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Check_Travel_by'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Travel by must be entered Air or Surface or Air/Surface.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # check Type and 0 < value
                elif serializer.errors.get('check_value_type'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Value of good must be entered intger number.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('check_value_0'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid value of goods, Please Enter correct value")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('check_weight_type'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Weight must be entered intger (grams) number.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('check_weight_0'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Weight, Please Enter correct weight")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Dimension
                elif serializer.errors.get('no_parcel'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Shipment type must be entered Parcel.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_dimension'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Dimension must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('no_volumetric_weight'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Volumetric weight must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Taxable value

                elif serializer.errors.get('check_taxable_amt_type'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Taxable value must be entered decimal number (000.00).")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('check_taxable_0'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Taxable amount, Please Enter correct Taxable amount")},
                        status=status.HTTP_400_BAD_REQUEST)

                # GST
                elif serializer.errors.get('check_sgst_0'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid SGST amount, Please Enter correct SGST amount")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('check_cgst_0'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid CGST amount, Please Enter correct CGST amount")},
                        status=status.HTTP_400_BAD_REQUEST)

                # PickUp Charge
                elif serializer.errors.get('check_pickup_charge_type'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("PickUp charge must be entered Intget number.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('check_pickup_charge_0'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid PickUp charge, Please Enter correct PickUp charge.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Total Charge
                elif serializer.errors.get('check_totalcharge_0'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Invalid Total charge, Please Enter correct Total charge.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # Booking Term & Condition
                elif serializer.errors.get('No_booking_tnc'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Booking tnc must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('false_booking_tnc'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Booking tnc must be True.")},
                        status=status.HTTP_400_BAD_REQUEST)

                # e-way Bill
                elif serializer.errors.get('no_eway_bill_no'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Eway bill number must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('eway_bill_date'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Eway bill date must be entered.")},
                        status=status.HTTP_400_BAD_REQUEST)

                elif serializer.errors.get('Check_eway_bill_number'):
                    return Response({
                        "response_code": 400,
                        "response_message": _("Eway bill date must be entered in numeric.")},
                        status=status.HTTP_400_BAD_REQUEST)

                return Response({"response_code": 400, "response_message": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            Error_Log(e)
            return Response({"response_code": 400, "response_message": _(e)}, status=status.HTTP_400_BAD_REQUEST)


"""
*****************
    List Order Details 
*****************
"""


class List_Order_EndUser_Views(GenericAPIView):

    authentication_classes = [JWTAuthentication]
    # permission_classes = [permissions.IsAdminUser]
    permission_classes = [permissions.AllowAny]

    serializer_class = EndUser_Order_Serializers

    @swagger_auto_schema(tags=["EndUser Order"], operation_description=("Payload:", '{"UserCard_id": Intger, "Owner_name": "String","card_number": "String","exp_date (Only Number)" : "string(mm/yy)"}'),)
    def get(self, request, format=None):
        """===================== Authoratation  ====================="""
        # token = self.request.headers["Authorization"]
        # UserID = DecodeJWT(token)
        UserID = 100

        data = End_User_Order.objects.filter(
            Q(is_active=True) & Q(user_idEndOrder=UserID)).order_by("id")

        if data:
            serializer = self.serializer_class(
                data, many=True, context={"request": request})

            return Response(
                {"responseCode": 200,
                 'responseMessage': _("Success"),
                 #  'responseData': encrypt_data(OrderDict_to_json(serializer.data))},
                 'responseData': serializer.data},
                status=status.HTTP_200_OK)
        else:
            return Response(
                {"responseCode": 404,
                 'responseMessage': _("No Data"), },
                status=status.HTTP_404_NOT_FOUND)
