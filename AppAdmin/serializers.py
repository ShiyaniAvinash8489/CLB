"""
*************************************
        Imported Packages 
*************************************
"""

# Serializer
from dataclasses import field
from email.policy import default
from rest_framework import serializers

# DateTime
from datetime import datetime

# Translation
from django.utils.translation import gettext_lazy as _

# Setting.py
from django.conf import settings

# Regular Expression
import re

# Authutication
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator

# Default Util - Forget Password
from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode

# JSON
import json

# Q Object
from django.db.models import Q

# DRF Extra Field
from drf_extra_fields.fields import HybridImageField, Base64ImageField

# Encrypt Decrypt
from AppAdmin.EncryptDecrypt import encrypt_data, decrypt_data, Json_decrypt_data

# Twilio Settings
from twilio.rest import Client

# Admin Models
from AppAdmin.models import (
    # Custom User
    User,

    # System & Device Log
    SystemAndDeviceLog,

    # Pincode Model
    Pincode_DB,

    # Booking Slot
    BookingSlot,

    # CLB Review
    CLB_Review,
    Courier_Company_Review,

    # Courier Company
    CourierCompany,

    # Price
    PriceForCustomer,
    Our_Price,

    # FAQ
    FAQ,
    FAQ_Cateogry,


    # Contact us
    ContactUs,


    # Ticket Support
    Issue_Category,
    Support_Ticket,

    # Notification
    Notification,

    # Banner
    Banner,

    # Offer
    Offer_discount,

)

# Agent Models
from AppAgent.models import (
    Agent_Bank_Details,
    Agent_KYC,
)


"""
**************************************************************************
                            Create Your Serializers here 
**************************************************************************
"""

# Twilio Settings
client = Client(settings.TWILIO_SID, settings.TWILIO_AUTH_TOKEN)
verify = client.verify.services(settings.TWILIO_SERVICE_ID)

"""
****************************************************************************************************************************************************************
                                                                 Admin
****************************************************************************************************************************************************************
"""


"""
********************
    Register Admin
********************
"""


class RegisterAdminUser_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = User
        fields = [
            'id',  'user_tnc', 'data'
        ]

        read_only_fields = ['id']
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False},
            'username': {'required': False},
            'country_code': {'required': False},
            'phone': {'required': False},
            'email': {'required': False},
            'password': {'required': False},
        }

    # Validate Data

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)
        user_tnc = validated_data.get('user_tnc')

        # Exists Data
        username_exists = User.objects.filter(
            username=decrypt_datas["username"]).exists()
        email_exists = User.objects.filter(email=decrypt_datas["email"])
        phone_exists = User.objects.filter(phone=decrypt_datas["phone"])

        if len(decrypt_datas["password"]) < 6 or len(decrypt_datas["password"]) > 25:
            raise serializers.ValidationError({"Password_Length": _(
                "Passwords must be bewtween 6  to 25 Characters.")})
        if user_tnc != True:
            raise serializers.ValidationError(
                {"user_tnc": _("Please agree to all the term and condition")})

        # Exists
        elif username_exists:
            raise serializers.ValidationError(
                {"username_exists": _("username already is existed.")})
        elif email_exists:
            raise serializers.ValidationError(
                {"email_exists": _("Email is already existed.")})
        elif phone_exists:
            raise serializers.ValidationError(
                {'phone_exists': _("Phone Number is already exists.")})

        # Validation
        # Email
        elif not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', decrypt_datas["email"]):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the correct E-Mail.")})

        # Username
        elif not re.match('^[a-zA-Z0-9].[a-zA-Z0-9\.\-_]*[a-zA-Z0-9]$', decrypt_datas["username"]):
            raise serializers.ValidationError(
                {"Username_validation": _("Username must be Alphanumeric & Special Character ('-','.','_')")})

        # Country Code
        elif not re.match('^[+][0-9]*$', decrypt_datas["country_code"]):
            raise serializers.ValidationError(
                {"Country Code": _("Country must be start with '+', and Numeric")})

        # Phone
        # Phone Digit
        elif not decrypt_datas["phone"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})
        # Phone Length
        elif len(decrypt_datas["phone"]) < 8 or len(decrypt_datas["phone"]) > 12:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 12 Characters")})

        # First Name
        elif not decrypt_datas["first_name"].isalpha() or not decrypt_datas["last_name"].isalpha():
            raise serializers.ValidationError(
                {"FirstName_validation": _("First Name and Last Name must be alphbet.")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["user_tnc"] = validated_data["user_tnc"]

        return User.objects.create_user(user_type="Admin", is_staff=True, **decrypt_datas)


class UpdateAdminUser_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = User
        fields = [
            'id',  'data'
        ]

        read_only_fields = ['id']
        extra_kwargs = {
            'first_name': {'required': False},
            'last_name': {'required': False},
            'username': {'required': False},
            'country_code': {'required': False},
            'phone': {'required': False},
            'email': {'required': False},
        }

    # Validate Data

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        # first_name = decrypt_datas["first_name"]
        # last_name = decrypt_datas["last_name"]
        # username = decrypt_datas["username"]
        # country_code = decrypt_datas["country_code"]
        # phone = decrypt_datas["phone"]
        # email = decrypt_datas["email"]

        # Exists Data
        username_exists = User.objects.filter(
            username=decrypt_datas["username"]).exists()
        email_exists = User.objects.filter(email=decrypt_datas["email"])
        phone_exists = User.objects.filter(phone=decrypt_datas["phone"])
        # Exists
        if username_exists:
            raise serializers.ValidationError(
                {"username_exists": _("username already is existed.")})
        elif email_exists:
            raise serializers.ValidationError(
                {"email_exists": _("Email is already existed.")})
        elif phone_exists:
            raise serializers.ValidationError(
                {'phone_exists': _("Phone Number is already exists.")})

        # Validation
        # Email
        elif not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', decrypt_datas["email"]):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the correct E-Mail.")})

        # Username
        elif not re.match('^[a-zA-Z0-9].[a-zA-Z0-9\.\-_]*[a-zA-Z0-9]$', decrypt_datas["username"]):
            raise serializers.ValidationError(
                {"Username_validation": _("Username must be Alphanumeric & Special Character ('-','.','_')")})

        # Country Code
        elif not re.match('^[+][0-9]*$', decrypt_datas["country_code"]):
            raise serializers.ValidationError(
                {"Country Code": _("Country must be start with '+', and Numeric")})

        # Phone
        # Phone Digit
        elif not decrypt_datas["phone"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})
        # Phone Length
        elif len(decrypt_datas["phone"]) < 8 or len(decrypt_datas["phone"]) > 12:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 12 Characters")})

        # First Name
        elif decrypt_datas["first_name"].isalpha() or decrypt_datas["last_name"].isalpha():
            raise serializers.ValidationError(
                {"FirstName_validation": _("First Name and Last Name must be alphbet.")})

        return validated_data

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        instance.first_name = decrypt_datas['first_name']
        instance.last_name = decrypt_datas['last_name']
        instance.username = decrypt_datas['username']
        instance.country_code = decrypt_datas['country_code']
        instance.phone = decrypt_datas['phone']
        instance.email = decrypt_datas['email']

        instance.save()

        return instance


class ChangePassword_Serializer(serializers.Serializer):

    model = User

    """
    Serializer for password change endpoint.
    """
    # old_password = serializers.CharField(required=True)
    # new_password = serializers.CharField(required=True)
    data = serializers.CharField(required=True)


"""
********************
    Verify Email 
********************
"""


class EmailVerification_Serializers(serializers.ModelSerializer):

    token = serializers.CharField(max_length=555)

    class Meta:
        model = User
        fields = ["token"]


"""
********************
    Super Admin Login  
********************
"""


class SuperAdminLogin_Serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = User
        fields = ["id", "data", ]

        read_only_fields = ["id", ]
        extra_kwargs = {
            'email': {'required': False},
            'password': {'required': False},
        }

    def validate(self, attrs):
        data = attrs.get("data")
        decrypt_datas = Json_decrypt_data(data)

        email = decrypt_datas["email"]
        password = decrypt_datas["password"]
        try:
            phone = User.objects.get(email=email).phone
            user = auth.authenticate(phone=phone, password=password)

            # Raise AuthenticationFailed
            if not user:
                raise serializers.ValidationError(
                    {"Invalid_Credentials": _('Invalid credentials, try again')})
            elif not user.is_verify:
                raise serializers.ValidationError(
                    {"Isverify": _('Admin User is not Active')})
            elif not user.is_superuser or not user.is_staff or not user.user_type == "Admin":
                raise serializers.ValidationError(
                    {"Normal_User": _('Only, Super Admin will allow to login.')})
        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"Invalid_Credentials": _('Invalid credentials, try again')})
        return attrs


class AdminLogin_Serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = User
        fields = ["id", "data", ]

        read_only_fields = ["id", ]
        extra_kwargs = {
            'email': {'required': False},
            'password': {'required': False},
        }

    def validate(self, attrs):
        data = attrs.get("data")
        decrypt_datas = Json_decrypt_data(data)

        email = decrypt_datas["email"]
        password = decrypt_datas["password"]
        try:
            phone = User.objects.get(email=email).phone
            user = auth.authenticate(phone=phone, password=password)

            # Raise AuthenticationFailed
            if not user:
                raise serializers.ValidationError(
                    {"Invalid_Credentials": _('Invalid credentials, try again')})
            elif not user.is_verify:
                raise serializers.ValidationError(
                    {"Isverify": _('Admin User is not Active')})
            elif not user.is_staff or not user.user_type == "Admin":
                raise serializers.ValidationError(
                    {"Normal_User": _('Only, Admin will allow to login.')})
        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"Invalid_Credentials": _('Invalid credentials, try again')})
        return attrs


"""
********************
    Forget Pasword 
********************
"""


# Send email request for forgetting Password
class ResetPasswordEmailRequest_Serializer(serializers.Serializer):

    # email = serializers.EmailField(min_length=1)
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )
    '''
    Below Comment Line was using redirects URL 
    
    '''
    # redirect_url = serializers.CharField(max_length=500, required=False)

    class Meta:
        fields = ['data']


# Set Forget Password
class SetNewPassword_Serializer(serializers.Serializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        fields = ['data']

    def validate(self, attrs):
        data = attrs.get("data")
        decrypt_datas = Json_decrypt_data(data)

        password = decrypt_datas["password"]

        if len(password) < 6 or len(password) > 25:
            raise serializers.ValidationError({"Password_Length": _(
                "Passwords must be bewtween 6  to 25 Characters.")})

        token = decrypt_datas["token"]
        uidb64 = decrypt_datas["uidb64"]
        # token = attrs.get('token')
        # uidb64 = attrs.get('uidb64')

        id = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=id)

        if not PasswordResetTokenGenerator().check_token(user, token):
            # raise AuthenticationFailed(_('The reset link is invalid'), 401)
            raise serializers.ValidationError({"Reset_Link": _(
                "The Reset link is invalid")})

        user.set_password(password)
        user.save()
        return (user)


"""
********************
    Get User Details 
********************
"""


class GetUserDetails_serializers(serializers.ModelSerializer):

    class Meta:
        model = User
        exclude = ('password', 'auth_provider', 'profile_images',
                   'groups', 'user_permissions')


"""
********************
    Search User
********************
"""


class Search_User_Serializres(serializers.ModelSerializer):
    profile_images = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = User
        fields = ["first_name", "middle_name", "last_name", "username", "country_code", "phone", "email", "password", "user_type", "latitude", "longitude",
                  "auth_provider", "is_active", "is_verify", "user_tnc", "is_staff", "created_on", "created_by", "updated_on", "updated_by", "profile_images"]


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


class SystemAndDeviceLog_Serializers(serializers.ModelSerializer):

    class Meta:

        model = SystemAndDeviceLog
        fields = ["user_idSysLog", "date_time", "os_type", "os_version",
                  "device_id", "device_type", "fcm_token", "active_fcm", "browser", "brower_version"]

        read_only_fields = ['date_time']


"""
********************
    Encrypt & Decrypt
********************
"""


class Encrypt_Serailizers(serializers.Serializer):

    encrypt_Data = serializers.CharField(max_length=500, required=False,
                                         write_only=True)

    class Meta:
        fields = ["encrypt_Data"]


class Decrypt_Serailizers(serializers.Serializer):

    decrypt_Data = serializers.CharField(max_length=5000, required=False,
                                         write_only=True)

    class Meta:
        fields = ["decrypt_Data"]


"""
********************
    Import CSV File 
********************
"""


class ImportCSVFileSerializers(serializers.Serializer):
    file = serializers.FileField()


"""
****************************************************************************************************************************************************************
                                                                Pincode 
****************************************************************************************************************************************************************
"""


"""
********************
    Get Single Pincode 
********************
"""


class Pincode_serializers(serializers.ModelSerializer):
    CC_Name = serializers.CharField(
        source="CC_Pin_id.name", required=False)

    class Meta:
        model = Pincode_DB
        fields = ["id", "CC_Pin_id", "CC_Name", "pincode", "Area_Name", "City", "State",
                  "Country", "is_clb_pickup",  "is_delivery", "is_active", "created_on",
                  "created_by", "updated_on", "updated_by"]

        read_only_fields = ['id', "CC_Name", "created_on",
                            "created_by", "updated_on", "updated_by"]

    def validate(self, attrs):
        CC_Pin_id = attrs.get("CC_Pin_id")
        pincode = attrs.get("pincode")

        Exists_Pincode = Pincode_DB.objects.filter(Q(CC_Pin_id=CC_Pin_id) & Q(
            pincode=pincode)).exists()
        if Exists_Pincode:
            raise serializers.ValidationError({"Pincode_Exists": _(
                "Already, Pincode is existed.")})

        return super().validate(attrs)


"""
****************************************************************************************************************************************************************
                                                                Booking Slot  
****************************************************************************************************************************************************************
"""


"""
********************
    Booking Slot  
********************
"""


class Admin_BookSlot_Serializers(serializers.ModelSerializer):

    class Meta:
        model = BookingSlot

        fields = ['id', "start_time",  "end_time",  "allow_time_after_start_time", "is_active", "created_on",
                  "created_by", "updated_on", "updated_by"]

        read_only_fields = ['id', "created_on",
                            "created_by", "updated_on", "updated_by"]

    def validate(self, attrs):
        start_time = attrs.get("start_time")
        end_time = attrs.get("end_time")
        allow_time_after_start_time = attrs.get("allow_time_after_start_time")

        if start_time > end_time:
            raise serializers.ValidationError(
                {"Invalid_Time": _("End time is less than Start Time")})

        elif start_time > allow_time_after_start_time or end_time < allow_time_after_start_time:
            raise serializers.ValidationError({
                "invalid_Allow_time": "Allow time is less than start or greater than end time. "})

        return super().validate(attrs)


"""
****************************************************************************************************************************************************************
                                                                Agent Verify Account  
****************************************************************************************************************************************************************
"""


"""
********************
    Agent - Verify KYC & Bank 
********************
"""


class Agent_Verify_KYC_byAdmin_Serializers(serializers.ModelSerializer):

    class Meta:
        model = Agent_KYC
        fields = ["id", "is_verify"]


class Agent_Verify_Bank_byAdmin_Serializers(serializers.ModelSerializer):

    class Meta:
        model = Agent_Bank_Details
        fields = ["id", "is_verify", "is_active"]


"""
****************************************************************************************************************************************************************
                                                                Courier Company   
****************************************************************************************************************************************************************
"""


"""
********************
    Couerier Company - Enctrypt & Decrypt 
********************
"""


class Courier_Company_Serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    logo = Base64ImageField(use_url=True, required=False)
    GST_Img = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = CourierCompany
        fields = ["id", "data", "GST_Img", "logo"]

    read_only_fields = ['id']
    extra_kwargs = {
        'name': {'required': False},
        'address': {'required': False},
        'GST_number': {'required': False},
        'PanCard_number': {'required': False},
        'contact_person_name': {'required': False},
        'contact_number': {'required': False},
        'email': {'required': False},
        'website': {'required': False},
    }

    # Validate Data

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        # Exists Data
        GSTNumber_exists = CourierCompany.objects.filter(
            GST_number=decrypt_datas["GST_number"]).exists()
        Pan_exists = CourierCompany.objects.filter(
            PanCard_number=decrypt_datas["PanCard_number"]).exists()
        email_exists = CourierCompany.objects.filter(
            email=decrypt_datas["email"]).exists()
        website_exists = CourierCompany.objects.filter(
            website=decrypt_datas["website"]).exists()

        # Exists
        if GSTNumber_exists:
            raise serializers.ValidationError(
                {"GSTNumber_exists": _("GST number already is existed.")})
        elif Pan_exists:
            raise serializers.ValidationError(
                {"Pan_exists": _("Pan Card number is already existed.")})
        elif email_exists:
            raise serializers.ValidationError(
                {"email_exists": _("Email is already existed.")})
        elif website_exists:
            raise serializers.ValidationError(
                {'website_exists': _("WebSite is already exists.")})

        elif not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', decrypt_datas["email"]):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the correct E-Mail.")})

        # Phone Digit
        elif not decrypt_datas["contact_number"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})

        # Phone Length
        elif len(decrypt_datas["contact_number"]) < 8 or len(decrypt_datas["contact_number"]) > 15:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 15 Characters")})

        # GST Length
        elif len(decrypt_datas["GST_number"]) != 15 or not decrypt_datas["GST_number"].isalnum():
            raise serializers.ValidationError(
                {"GST_Validation": _("Invalid GST Number please Enter Correct. ")})

        # GST Length
        elif len(decrypt_datas["PanCard_number"]) != 10 or not decrypt_datas["PanCard_number"].isalnum():
            raise serializers.ValidationError(
                {"Pancard_Validation": _("Invalid PanCard Number please Enter Correct. ")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["logo"] = validated_data["logo"]

        if "GST_Img" not in validated_data:
            return CourierCompany.objects.create(**decrypt_datas)
        else:
            decrypt_datas["GST_Img"] = validated_data["GST_Img"]
            return CourierCompany.objects.create(**decrypt_datas)


"""
********************
    List Courier Company 
********************
"""


class Courier_Copmany_List_Delete_serializers(serializers.ModelSerializer):
    logo = Base64ImageField(use_url=True, required=False)
    GST_Img = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = CourierCompany
        fields = ["id", "name", "logo", "address", "GST_number", "GST_Img", "PanCard_number", "contact_person_name",
                  "contact_number", "email", "website", "is_active", "created_on", "created_by",  "updated_on", "updated_by"]


"""
****************************************************************************************************************************************************************
                                                                Review CLB & Courier Company   
****************************************************************************************************************************************************************
"""


"""
********************
    CLB Review 
********************
"""


class CLB_Review_Serializers(serializers.ModelSerializer):

    class Meta:
        model = CLB_Review
        fields = ["id", "review_answer", "comment", "Review_by", "created_on"]
        read_only_fields = ['id', "created_on", "Review_by", ]

    def validate(self, attrs):
        review_answer = attrs.get('review_answer')

        if review_answer < 1 or review_answer > 5:
            raise serializers.ValidationError(
                {"Review": "Review Rating between 0 to 5"}
            )
        return super().validate(attrs)


"""
********************
    Courier Company Review 
********************
"""


class Courier_Company_Review_Serializers(serializers.ModelSerializer):

    class Meta:
        model = Courier_Company_Review
        fields = ["id", "CC_id", "review_answer",
                  "comment", "Review_User", "created_on"]
        read_only_fields = ['id', "created_on", "Review_User", ]

    def validate(self, attrs):
        review_answer = attrs.get('review_answer')

        if review_answer < 1 or review_answer > 5:
            raise serializers.ValidationError(
                {"Review": "Review Rating between 0 to 5"}
            )
        return super().validate(attrs)


"""
****************************************************************************************************************************************************************
                                                                Price Serializers
****************************************************************************************************************************************************************
"""


"""
********************
    Create - Price for Customer Encrypt Format
********************
"""


class CreatePriceForCustomer_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = PriceForCustomer
        fields = [
            'id', 'data'
        ]

        read_only_fields = ['id']
        extra_kwargs = {
            'CC_Price_id': {'required': False},
            'ServiceType': {'required': False},
            'ShipmentType': {'required': False},
            'TravelBy': {'required': False},
            'Weight_From': {'required': False},
            'Weight_To': {'required': False},
            'Local': {'required': False},
            'State': {'required': False},
            'RestOfIndia': {'required': False},
        }

    # Validate Data

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        # Exists Data
        CourierCompany_exists = CourierCompany.objects.filter(
            id=decrypt_datas["CC_Price_id"]).exists()

        # Exists
        if not CourierCompany_exists:
            raise serializers.ValidationError(
                {"Courier_Company_Exists": _("Courier Company does not existed.")})

        # Service Type
        elif decrypt_datas["ServiceType"] not in ["Standard", "Priority"]:
            raise serializers.ValidationError(
                {'Invalid_ServiceType': _("Invalid Service Type.")})

        # Shipment Type
        elif decrypt_datas["ShipmentType"] not in ["Documents", "Parcel"]:
            raise serializers.ValidationError(
                {'Invalid_ShipmentType': _("Invalid Shipment Type.")})

        # Travel Type
        elif decrypt_datas["TravelBy"] not in ["Air", "Surface", "Air/Surface"]:
            raise serializers.ValidationError(
                {'Invalid_TravelType': _("Invalid Travel Type.")})

        # Weight From
        elif decrypt_datas["Weight_From"] < 0 or 1000 < decrypt_datas["Weight_From"] or decrypt_datas["Weight_To"] < 0 or 1000 < decrypt_datas["Weight_To"]:
            raise serializers.ValidationError(
                {"Weight_Limit": _("Weight should be between 0 to 1000")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["CC_Price_id"] = CourierCompany.objects.get(
            id=decrypt_datas["CC_Price_id"])

        return PriceForCustomer.objects.create(**decrypt_datas)


class ListPriceForCustomer_Serializers(serializers.ModelSerializer):

    class Meta:
        model = PriceForCustomer
        fields = '__all__'

        read_only_fields = ['id', 'created_on',
                            'created_by', 'updated_on', 'updated_by']


"""
********************
    Create - Price for US Encrypt Format
********************
"""


class CreatePriceForUS_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Our_Price
        fields = [
            'id', 'data'
        ]

        read_only_fields = ['id']
        extra_kwargs = {
            'CC_OurPrice_id': {'required': False},
            'ServiceType': {'required': False},
            'ShipmentType': {'required': False},
            'TravelBy': {'required': False},
            'Weight_From': {'required': False},
            'Weight_To': {'required': False},
            'Local': {'required': False},
            'State': {'required': False},
            'RestOfIndia': {'required': False},
        }

    # Validate Data

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)
        print(f"\n\n\n\n\n {decrypt_datas} \n\n\n\n")
        # Exists Data
        CourierCompany_exists = CourierCompany.objects.filter(
            id=decrypt_datas["CC_OurPrice_id"]).exists()

        # Exists
        if not CourierCompany_exists:
            raise serializers.ValidationError(
                {"Courier_Company_Exists": _("Courier Company does not existed.")})

        # Service Type
        elif decrypt_datas["ServiceType"] not in ["Standard", "Priority"]:
            raise serializers.ValidationError(
                {'Invalid_ServiceType': _("Invalid Service Type.")})

        # Shipment Type
        elif decrypt_datas["ShipmentType"] not in ["Documents", "Parcel"]:
            raise serializers.ValidationError(
                {'Invalid_ShipmentType': _("Invalid Shipment Type.")})

        # Travel Type
        elif decrypt_datas["TravelBy"] not in ["Air", "Surface", "Air/Surface"]:
            raise serializers.ValidationError(
                {'Invalid_TravelType': _("Invalid Travel Type.")})

        # Weight From
        elif decrypt_datas["Weight_From"] < 0 or 1000 < decrypt_datas["Weight_From"] or decrypt_datas["Weight_To"] < 0 or 1000 < decrypt_datas["Weight_To"]:
            raise serializers.ValidationError(
                {"Weight_Limit": _("Weight should be between 0 to 1000")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["CC_OurPrice_id"] = CourierCompany.objects.get(
            id=decrypt_datas["CC_OurPrice_id"])

        return Our_Price.objects.create(**decrypt_datas)


class ListPriceForUs_Serializers(serializers.ModelSerializer):

    class Meta:
        model = Our_Price
        fields = '__all__'

        read_only_fields = ['id', 'created_on',
                            'created_by', 'updated_on', 'updated_by']


"""
****************************************************************************************************************************************************************
                                                                Frequently Asked Questions
****************************************************************************************************************************************************************
"""

"""
*******************
    FAQ - Category - Ecrypt & Decrypt 
*******************
"""


class faq_category_encrypt_serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = FAQ_Cateogry
        fields = ["id", "data"]

        read_only_fields = ['id']
        extra_kwargs = {
            'name': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)
        print(f"\n\n\n\n\n {decrypt_datas} \n\n\n\n")

        # Exists
        if not re.match('^[a-zA-Z][a-zA-Z\s]*[a-zA-Z]$', decrypt_datas["name"]):
            raise serializers.ValidationError(
                {"name_alpha": _("Category must be entered only alphbet.")})
        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        return FAQ_Cateogry.objects.create(**decrypt_datas)

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        instance.name = decrypt_datas['name']
        instance.save()

        return instance


"""
*******************
    FAQ - Category - LIST 
*******************
"""


class faq_category_serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = FAQ_Cateogry
        fields = "__all__"
        read_only_fields = ['id', 'created_on',
                            'created_by', 'updated_on', 'updated_by']

    def validate(self, validated_data):
        name = validated_data.get("name")

        if not name.isalpha():
            raise serializers.ValidationError(
                {"name_alpha": _("Category must be entered only alphbet.")})

        return validated_data


"""
*******************
    FAQ - Ecrypt & Decrypt 
*******************
"""


class faq_ecrypt_serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = FAQ
        fields = [
            'id', 'data'
        ]

        read_only_fields = ['id']
        extra_kwargs = {
            'faq_category_id': {'required': False},
            'question': {'required': False},
            'answer': {'required': False},
        }

    # Validate Data

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        print(f"\n\n\n\n\n {decrypt_datas} \n\n\n\n")

        # Exists Data
        FAQCategory_exists = FAQ_Cateogry.objects.filter(
            id=decrypt_datas["faq_category_id"]).exists()

        # Exists
        if not FAQCategory_exists:
            raise serializers.ValidationError(
                {"FAQCategory_Exists": _("FAQ Category does not existed.")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["faq_category_id"] = FAQ_Cateogry.objects.get(
            id=decrypt_datas["faq_category_id"])

        return FAQ.objects.create(**decrypt_datas)

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        faq_category_idq = FAQ_Cateogry.objects.get(
            id=decrypt_datas["faq_category_id"])

        instance.faq_category_id = faq_category_idq
        instance.question = decrypt_datas['question']
        instance.answer = decrypt_datas['answer']

        instance.save()

        return instance


"""
*******************
    FAQ - List 
*******************
"""


class faq_serializers(serializers.ModelSerializer):

    Category_name = serializers.CharField(
        source="faq_category_id.name", required=False)

    class Meta:
        model = FAQ
        fields = ["id", "Category_name", "faq_category_id", "question", "answer", 'created_on',
                  'created_by', 'updated_on', 'updated_by']
        read_only_fields = ['id', 'created_on',
                            'created_by', 'updated_on', 'updated_by']

    # Validate Data

    def validate(self, validated_data):
        faq_category_id = validated_data.get("faq_category_id")
        question = validated_data.get("question")
        answer = validated_data.get("answer")

        # Exists Data
        FAQCategory_exists = FAQ_Cateogry.objects.filter(
            id=faq_category_id).exists()

        # Exists
        if not FAQCategory_exists:
            raise serializers.ValidationError(
                {"FAQCategory_Exists": _("FAQ Category does not existed.")})

        return validated_data


"""
****************************************************************************************************************************************************************
                                                                Contact Us
****************************************************************************************************************************************************************
"""


class CountactUs_Serializers(serializers.ModelSerializer):

    class Meta:
        model = ContactUs
        fields = '__all__'
        read_only_fields = ['id', 'solve_timeshtamp', 'solve_by', 'created_on',
                            'created_by', 'updated_on', 'updated_by']

    def validate(self, validated_data):
        name = validated_data.get("name")
        phone = validated_data.get("phone")
        email = validated_data.get("email")

        if not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', email):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the correct E-Mail.")})

        # Country Code
        elif not re.match('^[+][0-9]*$', phone):
            raise serializers.ValidationError(
                {"Country_Code": _("Country must be start with '+', and Numeric")})

        # Phone Length
        elif len(phone) < 10 or len(phone) > 15:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 10  to 12 Characters")})

        return validated_data


class CountactUs_Update_Serializers(serializers.ModelSerializer):

    class Meta:
        model = ContactUs
        fields = ['is_solve']
        read_only_fields = ['id', 'solve_timeshtamp', 'solve_by', 'created_on',
                            'created_by', 'updated_on', 'updated_by']


"""
****************************************************************************************************************************************************************
                                                                Ticket / Support 
****************************************************************************************************************************************************************
"""


"""
*******************
    FAQ - Category - Ecrypt & Decrypt 
*******************
"""


class issue_Category_encrypt_serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Issue_Category
        fields = ["id", "data"]

        read_only_fields = ['id']
        extra_kwargs = {
            'name': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)
        print(f"\n\n\n\n\n {decrypt_datas} \n\n\n\n")

        # Exists
        if not re.match('^[a-zA-Z][a-zA-Z\s]*[a-zA-Z]$', decrypt_datas["name"]):
            raise serializers.ValidationError(
                {"name_alpha": _("Category must be entered only alphbet.")})
        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        return Issue_Category.objects.create(**decrypt_datas)

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        instance.name = decrypt_datas['name']
        instance.save()

        return instance


"""
*******************
    FAQ - Category - LIST 
*******************
"""


class issue_Category_serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Issue_Category
        fields = "__all__"
        read_only_fields = ['id', 'created_on',
                            'created_by', 'updated_on', 'updated_by']

    def validate(self, validated_data):
        name = validated_data.get("name")

        if not name.isalpha():
            raise serializers.ValidationError(
                {"name_alpha": _("Category must be entered only alphbet.")})

        return validated_data


"""
********************************************************************************************************************************************
                                                            Supoort Ticket 
********************************************************************************************************************************************
"""


"""
**************************
        List Support Ticket
**************************
"""


class admin_SupportTicket_Serializers(serializers.ModelSerializer):
    Iss_Category_name = serializers.CharField(
        source="issue_Cate_id.Catename", required=False)

    class Meta:
        model = Support_Ticket
        fields = '__all__'


"""
**************************
        Update Support Ticket
**************************
"""


class SupportTicket_Admin_Encrypt_Serializres(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Support_Ticket
        fields = ["id", "data"]
        read_only_fields = ['id', ]
        extra_kwargs = {
            'is_closed': {'required': False},
            'closing_details': {'required': False},
            'status': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        if decrypt_datas["status"] == "Closed":

            if decrypt_datas["is_closed"] == False:
                raise serializers.ValidationError(
                    {'isClose_validation': _("Is_close is False, please check True it")})

            elif not decrypt_datas["closing_details"]:
                raise serializers.ValidationError(
                    {'close_Detail': _("Close details must not be empty.")})

            return validated_data

        else:

            if decrypt_datas["is_closed"] == True:
                raise serializers.ValidationError(
                    {'isClose_validation_else': _("Is_close is True, please check False it")})

            elif decrypt_datas["closing_details"]:
                raise serializers.ValidationError(
                    {'close_Detail_else': _("Close details must be empty.")})

            return validated_data

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        if decrypt_datas["status"] == "Closed":
            instance.status = decrypt_datas['status']
            instance.is_closed = True
            instance.closing_details = decrypt_datas['closing_details']
            instance.save()

            return instance

        else:
            instance.status = decrypt_datas['status']
            instance.is_closed = False
            instance.closing_details = decrypt_datas['closing_details']
            instance.save()

            return instance


"""
********************************************************************************************************************************************
                                                            Notification
********************************************************************************************************************************************
"""


class Notification_Serializers(serializers.ModelSerializer):

    Notif_image = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = Notification
        fields = ["id", "usersType", "title", "body", "Notif_image"]

        read_only_fields = ['id', "is_active", "created_on",
                            "created_by", "updated_on", "updated_by"]


"""
********************************************************************************************************************************************
                                                            Banner 
********************************************************************************************************************************************
"""


"""
**************************
        Create & Update Banner 
**************************
"""


class Banner_Encrypt_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    banner_image = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = Banner
        fields = ["id", "data", "banner_image"]
        read_only_fields = ["id", "banner_title",
                            "banner_caption", "banner_start", "banner_end", ]

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        if decrypt_datas["banner_start"] > decrypt_datas["banner_end"]:
            raise serializers.ValidationError(
                {"Invalid_Time": _("End time is less than Start Time")})

        return validated_data

    # Create user

    def create(self, validated_data):

        decrypt_datas = Json_decrypt_data(validated_data["data"])
        # decrypt_datas["banner_image"] = validated_data["banner_image"]

        if "banner_image" not in validated_data:
            return Banner.objects.create(**decrypt_datas)
        else:
            decrypt_datas["banner_image"] = validated_data["banner_image"]
            return Banner.objects.create(**decrypt_datas)

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        if "banner_image" not in validated_data:
            instance.banner_title = decrypt_datas['banner_title']
            instance.banner_caption = decrypt_datas['banner_caption']
            instance.banner_start = decrypt_datas['banner_start']
            instance.banner_end = decrypt_datas['banner_end']
            instance.save()
            return instance

        else:
            instance.banner_title = decrypt_datas['banner_title']
            instance.banner_caption = decrypt_datas['banner_caption']
            instance.banner_start = decrypt_datas['banner_start']
            instance.banner_end = decrypt_datas['banner_end']
            instance.banner_image = validated_data["banner_image"]
            instance.save()

            return instance


"""
**************************
        Normal Banner 
**************************
"""


class banner_serializers(serializers.ModelSerializer):
    banner_image = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = Banner
        fields = ["id", "banner_title", "banner_caption", "banner_start",
                  "banner_end", "banner_image", "created_on", "created_by", "updated_on", "updated_by"]


"""
********************************************************************************************************************************************
                                                            Offer 
********************************************************************************************************************************************
"""


"""
**************************
    Create Offer 
**************************
"""


class Offer_discount_encrypt_serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Offer_discount
        fields = ["id", "data"]
        read_only_fields = ["id", "offer_name",
                            "offer_description", "offer_code", "offer_amount", "offer_percentage", "offer_upto_value", "offer_minium_value", "offer_start", "offer_end"]

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        # Blank Validation
        if decrypt_datas["offer_name"].isspace() or not decrypt_datas["offer_name"]:
            raise serializers.ValidationError(
                {"offer_name_blank_validation": _("Offer name must not be empty.")})

        elif decrypt_datas["offer_description"].isspace() or not decrypt_datas["offer_description"]:
            raise serializers.ValidationError(
                {"offer_description_blank_validation": _("Offer description must not be empty.")})

        elif decrypt_datas["offer_code"].isspace() or not decrypt_datas["offer_code"]:
            raise serializers.ValidationError(
                {"offer_code_blank_validation": _("Offer code must not be empty.")})

        elif not decrypt_datas["offer_minium_value"]:
            raise serializers.ValidationError(
                {"offer_minium_value_blank_validation": _("Offer minium_value must not be empty.")})

        elif not decrypt_datas["offer_start"]:
            raise serializers.ValidationError(
                {"offer_start_blank_validation": _("Offer start must not be empty.")})

        elif not decrypt_datas["offer_end"]:
            raise serializers.ValidationError(
                {"offer_end_blank_validation": _("Offer end must not be empty.")})

        # Time Validation
        if decrypt_datas["offer_start"] > decrypt_datas["offer_end"]:
            raise serializers.ValidationError(
                {"Invalid_Time": _("End time is less than Start Time")})

        # Amount & % & up to value
        if "offer_amount" in decrypt_datas and "offer_percentage" in decrypt_datas and "offer_upto_value" in decrypt_datas:
            raise serializers.ValidationError(
                {"Invalid_fields": _("You shuld enter Offer amount or (offer percentage and offer upto value)")})

        # offer amount validation
        if "offer_amount" in decrypt_datas and "offer_percentage" not in decrypt_datas and "offer_upto_value" not in decrypt_datas:
            if not decrypt_datas["offer_amount"]:
                raise serializers.ValidationError(
                    {"offer_amount_blank_validation": _("Offer amount must not be empty.")})

            if decrypt_datas["offer_amount"] < 0:
                raise serializers.ValidationError(
                    {"offer_amount_zero": _("Offer amount must be greater than 0 (zero).")})

        # Offer Percentage & Upto value
        if "offer_percentage" in decrypt_datas and "offer_upto_value" in decrypt_datas and "offer_amount" not in decrypt_datas:

            if not decrypt_datas["offer_percentage"]:
                raise serializers.ValidationError(
                    {"offer_percentage_blank_validation": _("Offer percentage must not be empty.")})

            elif not decrypt_datas["offer_upto_value"]:
                raise serializers.ValidationError(
                    {"offer_upto_valueblank_validation": _("Offer upto value must not be empty.")})

            elif decrypt_datas["offer_percentage"] < 0 or decrypt_datas["offer_percentage"] > 99.99:
                raise serializers.ValidationError(
                    {"offer_percentage_zero": _("Offer percentage must be between o and 99.99.")})

            elif decrypt_datas["offer_upto_value"] < 0:
                raise serializers.ValidationError(
                    {"offer_upto_value_zero": _("Offer upto amount must be greater than 0 (zero).")})
        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        if "offer_amount" in decrypt_datas:
            return Offer_discount.objects.create(**decrypt_datas)

        elif "offer_percentage" in decrypt_datas and "offer_upto_value" in decrypt_datas:
            return Offer_discount.objects.create(**decrypt_datas)

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        if "amount" in decrypt_datas:
            instance.offer_name = decrypt_datas['offer_name']
            instance.offer_description = decrypt_datas['offer_description']
            instance.offer_code = decrypt_datas['offer_code']
            instance.offer_minium_value = decrypt_datas['offer_minium_value']
            instance.offer_start = decrypt_datas['offer_start']
            instance.offer_end = decrypt_datas['offer_end']
            instance.offer_amount = decrypt_datas['offer_amount']
            instance.save()
            return instance

        elif "offer_percentage" in decrypt_datas and "offer_upto_value" in decrypt_datas:
            instance.offer_name = decrypt_datas['offer_name']
            instance.offer_description = decrypt_datas['offer_description']
            instance.offer_code = decrypt_datas['offer_code']
            instance.offer_minium_value = decrypt_datas['offer_minium_value']
            instance.offer_start = decrypt_datas['offer_start']
            instance.offer_end = decrypt_datas['offer_end']
            instance.offer_percentage = decrypt_datas['offer_percentage']
            instance.offer_upto_value = decrypt_datas['offer_upto_value']
            instance.save()

            return instance


"""
**************************
        Normal Offer 
**************************
"""


class Offer_discount_serializers(serializers.ModelSerializer):

    class Meta:
        model = Offer_discount
        fields = '__all__'
