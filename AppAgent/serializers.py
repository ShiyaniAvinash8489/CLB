"""
*************************************
        Imported Packages 
*************************************
"""

# Serializer
from dataclasses import field
from time import process_time_ns
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
)


# Agent Model
from AppAgent.models import (
    Agent_Address,
    Agent_Bank_Details,
    Agent_KYC,
    Agent_Verify_Email_Mobile,
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
    Verify Email & Phone
********************
"""


class VerifyEmailPhone_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Agent_Verify_Email_Mobile
        fields = [
            'id', 'data'
        ]

        read_only_fields = ['id']
        extra_kwargs = {
            'email': {'required': False},
            'country_code': {'required': False},
            'phone': {'required': False},
        }

    # Validate Data

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        # Exists Data

        User_email_exists = User.objects.filter(
            email=decrypt_datas["email"]).exists()
        User_phone_exists = User.objects.filter(
            phone=decrypt_datas["phone"]).exists()
        Agent_email_exists = Agent_Verify_Email_Mobile.objects.filter(
            Q(email=decrypt_datas["email"]) & Q(is_verify_email=False)).exists()
        Agent_Phone_exists = Agent_Verify_Email_Mobile.objects.filter(
            Q(email=decrypt_datas["phone"]) & Q(is_verify_email=False)).exists()

        # Exists

        if User_email_exists:

            if Agent_email_exists:
                Agent_Verify_Email_Mobile.objects.filter(
                    Q(email=decrypt_datas["email"]) & Q(is_verify_email=False)).delete()
            else:
                raise serializers.ValidationError(
                    {"email_exists": _("Email is already existed.")})

        if User_phone_exists:
            if Agent_Phone_exists:
                Agent_Verify_Email_Mobile.objects.filter(
                    Q(email=decrypt_datas["email"]) & Q(is_verify_email=False)).delete()
            else:
                raise serializers.ValidationError(
                    {'phone_exists': _("Phone Number is already exists.")})

        # Validation
        # Email
        if not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', decrypt_datas["email"]):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the correct E-Mail.")})

        # Country Code
        elif not re.match('^[+][0-9]*$', decrypt_datas["country_code"]):
            raise serializers.ValidationError(
                {"Country Code": _("Country must be start with '+', and Numeric")})

        # Phone Digit
        elif not decrypt_datas["phone"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})

        # Phone Length
        elif len(decrypt_datas["phone"]) < 8 or len(decrypt_datas["phone"]) > 12:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 12 Characters")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        return Agent_Verify_Email_Mobile.objects.create(**decrypt_datas)


class Verify_Email_OTP_serializers(serializers.Serializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class META:
        fields = ["data"]

    def validate(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data.get("data"))

        if not decrypt_datas["otpCode"].isdigit():
            raise serializers.ValidationError(
                {"otp_Digit": _("OTP must be Only Numberic")})

        return validated_data


"""
********************
    Register Agent 
********************
"""


class RegisterAgentUser_Serializers(serializers.ModelSerializer):

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
            'middle_name': {'required': False},
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
        elif not decrypt_datas["first_name"].isalpha() or not decrypt_datas["last_name"].isalpha() or not decrypt_datas["middle_name"].isalpha():
            raise serializers.ValidationError(
                {"FirstName_validation": _("First Name and Last Name must be alphbet.")})

        # Email - Verify
        if (Agent_Verify_Email_Mobile.objects.filter(
                Q(email=decrypt_datas["email"]) & Q(is_verify_email=False))) or not Agent_Verify_Email_Mobile.objects.filter(
                email=decrypt_datas["email"]).exists():
            raise serializers.ValidationError(
                {"Not_Verify_Email": _("Register Email is not virefy. ")})

        # Phone - Verify
        if (Agent_Verify_Email_Mobile.objects.filter(
                Q(phone=decrypt_datas["phone"]) & Q(is_verify_phone=False))) or not Agent_Verify_Email_Mobile.objects.filter(
                phone=decrypt_datas["phone"]).exists():
            raise serializers.ValidationError(
                {"Not_Verify_phone": _("Register Phone is not virefy. ")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["user_tnc"] = validated_data["user_tnc"]

        return User.objects.create_user(user_type="Agent", is_staff=False, created_by="Self", **decrypt_datas)


"""
********************
    Agent Address
********************
"""


class Agent_Address_Serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Agent_Address
        fields = ['id',   'data']

        read_only_fields = ['id']
        extra_kwargs = {
            'user_id': {'required': False},
            'address_line_1': {'required': False},
            'address_line_2': {'required': False},
            'landmarks': {'required': False},
            'city': {'required': False},
            'state': {'required': False},
            'pincode': {'required': False},
            'country': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        User_exists = User.objects.filter(id=decrypt_datas["user_id"]).exists()

        if not User_exists:
            raise serializers.ValidationError({"User_Exists": _(
                "User does not exists.")})

        if not decrypt_datas["user_id"]:
            raise serializers.ValidationError({"User_id": _(
                "You should enter user address.")})
        elif not decrypt_datas["address_line_1"]:
            raise serializers.ValidationError({"Add_1": _(
                "You should enter Address.")})
        elif not decrypt_datas["city"]:
            raise serializers.ValidationError({"Agent_city": _(
                "City must be enterd.")})
        elif not decrypt_datas["pincode"]:
            raise serializers.ValidationError({"Agent_pincode": _(
                "pincode must be enterd.")})

        return validated_data

    # Create user
    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        user_id = User.objects.get(id=decrypt_datas["user_id"])
        decrypt_datas["user_id"] = user_id

        return Agent_Address.objects.create(created_by="Self", **decrypt_datas)


"""
********************
    Agent Bank Details 
********************
"""


class Agent_Bank_Details_Serializers(serializers.ModelSerializer):

    cancel_cheque = Base64ImageField(use_url=True, required=False)
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Agent_Bank_Details
        fields = ['id',   'data', 'cancel_cheque']

        read_only_fields = ['id']
        extra_kwargs = {
            'user_id': {'required': False},
            'bank_name': {'required': False},
            'branch_name': {'required': False},
            'IFSC_code': {'required': False},
            'account_number': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        if not decrypt_datas["user_id"]:
            raise serializers.ValidationError({"User_id": _(
                "User Id must not be empty.")})

        if not decrypt_datas["bank_name"]:
            raise serializers.ValidationError({"bank_empty": _(
                "Bank Name must not be empty.")})

        elif not decrypt_datas["branch_name"]:
            raise serializers.ValidationError({"branch_empty": _(
                "Branch Name must not be empty.")})

        elif not decrypt_datas["IFSC_code"]:
            raise serializers.ValidationError({"ifsc_empty": _(
                "IFSC Code must not be empty.")})

        elif not decrypt_datas["IFSC_code"].isalnum():
            raise serializers.ValidationError({"ifsc_alphnum": _(
                "IFSC Code must be AlphaNumeric.")})

        elif not decrypt_datas["account_number"]:
            raise serializers.ValidationError({"account_empty": _(
                "Account Number must not be empty.")})

        elif not decrypt_datas["account_number"].isalnum():
            raise serializers.ValidationError({"account_alphnum": _(
                "Account Number must be AlphaNumeric.")})
        return validated_data

    # Create user

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        user_id = User.objects.get(id=decrypt_datas["user_id"])
        decrypt_datas["user_id"] = user_id
        decrypt_datas["cancel_cheque"] = validated_data["cancel_cheque"]

        return Agent_Bank_Details.objects.create(created_by="Self", **decrypt_datas)


"""
********************
    Agent KYC Details 
********************
"""


class Agent_KYC_Serializers(serializers.ModelSerializer):
    frontside_image = Base64ImageField(use_url=True)
    backside_image = Base64ImageField(use_url=True)
    UserKYCImage = Base64ImageField(use_url=True)

    class Meta:
        model = Agent_KYC
        fields = ["id", "user_idKYC", "KYC_Name",
                  "frontside_image", "backside_image", "UserKYCImage"]

        read_only_fields = ['id']


"""
********************
    Agent Login 
********************
"""


class Agent_Login_Serializers(serializers.ModelSerializer):
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
                    {"Isverify": _('Your account is not verified by admin.')})
            elif user.is_superuser or user.is_staff or not user.user_type == "Agent":
                raise serializers.ValidationError(
                    {"NonAgent_User": _('Only, Agent will allow to login.')})
            elif not user.is_active:
                raise serializers.ValidationError(
                    {"Active_User": _('Please, Contact to Admin. ')})

            # elif Agent_Bank_Details.objects.filter(Q(
            #         user_id__email=decrypt_datas["email"]) & Q(is_verify=False)):
            #     raise serializers.ValidationError(
            #         {"BankDetails": _('Your Bank account is not verified by admin ')})

            elif Agent_KYC.objects.filter(Q(
                    user_id__email=decrypt_datas["email"]) & Q(is_verify=False)):
                raise serializers.ValidationError(
                    {"KYC_Details": _('Your KYC is not verified by admin ')})

        except User.DoesNotExist:
            raise serializers.ValidationError(
                {"Invalid_Credentials": _('Invalid credentials, try again')})
        return attrs


"""
************
   Agent Update Profile 
************
"""


class Agent_Update_Profile_serializers(serializers.ModelSerializer):

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
            'middle_name': {'required': False},
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
        elif not decrypt_datas["first_name"].isalpha() or not decrypt_datas["last_name"].isalpha() or not decrypt_datas["middle_name"].isalpha():
            raise serializers.ValidationError(
                {"FirstName_validation": _("First Name and Last Name must be alphbet.")})

        # Email - Verify
        if (Agent_Verify_Email_Mobile.objects.filter(
                Q(email=decrypt_datas["email"]) & Q(is_verify_email=False))) or not Agent_Verify_Email_Mobile.objects.filter(
                email=decrypt_datas["email"]).exists():
            raise serializers.ValidationError(
                {"Not_Verify_Email": _("Register Email is not virefy. ")})

        # Phone - Verify
        if (Agent_Verify_Email_Mobile.objects.filter(
                Q(phone=decrypt_datas["phone"]) & Q(is_verify_phone=False))) or not Agent_Verify_Email_Mobile.objects.filter(
                phone=decrypt_datas["phone"]).exists():
            raise serializers.ValidationError(
                {"Not_Verify_phone": _("Register Phone is not virefy. ")})

        return validated_data

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        instance.first_name = decrypt_datas['first_name']
        instance.middle_name = decrypt_datas['middle_name']
        instance.last_name = decrypt_datas['last_name']
        instance.username = decrypt_datas['username']
        instance.country_code = decrypt_datas['country_code']
        instance.phone = decrypt_datas['phone']
        instance.email = decrypt_datas['email']

        instance.save()

        return instance


"""
************************************************************************************************************************************************
                                                        Serailizers - Admin
************************************************************************************************************************************************
"""

"""
Agent - KYC for Admin
"""


class Agent_KYC_for_admin_Serializers(serializers.ModelSerializer):
    frontside_image = Base64ImageField(use_url=True)
    backside_image = Base64ImageField(use_url=True)
    UserKYCImage = Base64ImageField(use_url=True)

    class Meta:
        model = Agent_KYC
        fields = '__all__'
        read_only_fields = ['id']


"""
Agent - Bank for Admin
"""


class Agent_Bank_Details_for_admin_Serializers(serializers.ModelSerializer):

    cancel_cheque = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = Agent_Bank_Details
        fields = '__all__'
        read_only_fields = ['id']
