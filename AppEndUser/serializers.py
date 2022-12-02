"""
*************************************
        Imported Packages
*************************************
"""

# Serializer
from dataclasses import field
from email.policy import default
from genericpath import exists
from rest_framework import serializers

# DateTime
from datetime import datetime

# Translation
from django.utils.translation import gettext_lazy as _

# Setting.py
from django.conf import settings

# Regular Expression
import re

# Q Object
from django.db.models import Q

# Error Logs
from AppAdmin.Error_Log import Error_Log

# DRF Extra Field
from drf_extra_fields.fields import HybridImageField, Base64ImageField

# Twilio Settings
from twilio.rest import Client
from django.conf import settings
from twilio.base import exceptions
from twilio.base.exceptions import TwilioRestException, TwilioException
from AppAdmin.FunctionGen import CheckTicketNumber, Check_And_Generate_Order_Number

# Encrypt Decrypt
from AppAdmin.EncryptDecrypt import encrypt_data, decrypt_data, Json_decrypt_data

# Models - Admin
from AppAdmin.models import (
    User,
    Pincode_DB,
    CLB_Review,
    CourierCompany,
    Courier_Company_Review,
    Issue_Category,
    Support_Ticket,
    Banner,
    Offer_discount,

)


# Models - EndUser
from AppEndUser.models import (
    Sender_Receiver_Address,
    User_Card_Details,
    End_User_Order,
    CourierCompany,
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
**************************************************************************
                                    Login 
**************************************************************************
"""


"""
**********
    End-Super Loing & Signup
**********
"""


class EndUserRegister_Login_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:

        model = User
        fields = [
            "data"
        ]

    def validate(self, attrs):
        decrypt_datas = Json_decrypt_data(attrs.get("data"))

        # Exists
        PhoneExist = User.objects.filter(
            Q(phone=decrypt_datas["phone"]) & Q(is_active=True))

        if not re.match('^[+][0-9]*$', decrypt_datas["country_code"]):
            raise serializers.ValidationError(
                {"country_code": _("Country Code must be start with '+', and Numeric")})

        elif len(decrypt_datas["phone"]) < 10 or len(decrypt_datas["phone"]) > 20:
            raise serializers.ValidationError(
                {"phone_length": _("Please enter phone number between 10 to 20 length'")})

        elif not decrypt_datas["phone"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})

        if not User.objects.filter(phone=decrypt_datas["phone"]):
            try:
                User.objects.create_user(
                    country_code=decrypt_datas["country_code"], phone=decrypt_datas["phone"], user_type="EndUser", is_verify=True, user_tnc=True)
                mobile = str(
                    decrypt_datas["country_code"]+decrypt_datas["phone"])

                verify.verifications.create(to=mobile, channel='sms')
                User.objects.filter(
                    phone=decrypt_datas["phone"]).update(created_by="Self")

                raise serializers.ValidationError(
                    {"register_otp": _("User is Successfully registered, OTP have been sent to resgister phone number.")})
            except TwilioException as e:
                Error_Log(e)
                raise serializers.ValidationError(
                    {"ErrorMessage": _(e.args[2])})
        if not PhoneExist:
            raise serializers.ValidationError(
                {"Delete_User": _("User is Deleted")})

        elif not User.objects.filter(phone=decrypt_datas["phone"], user_type="EndUser"):
            raise serializers.ValidationError(
                {"End_User": _("Only End user can Login. ")})

        return attrs


"""
**********
    Verify OTP  
**********
"""


class VerifyOTP_serializers(serializers.Serializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class META:
        fields = ["data"]

    def validate(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data.get("data"))

        # Phone
        if not re.match('^[+][0-9]*$', decrypt_datas["country_code"]):
            raise serializers.ValidationError(
                {"country_code_invalid": _("Country code must be start with '+', and Numeric")})

        elif len(decrypt_datas["phone"]) < 10 or len(decrypt_datas["phone"]) > 20:
            raise serializers.ValidationError(
                {"phone_length": _("Please enter phone number between 10 to 20 length'")})

        elif not decrypt_datas["phone"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})

        elif not decrypt_datas["otpCode"].isdigit():
            raise serializers.ValidationError(
                {"otp_Digit": _("OTP must be Only Numberic")})

        return validated_data


"""
**************************************************************************
                    Sender & Receiver Address 
**************************************************************************
"""


"""
**********
    Sender  - Encrypt -Decrypt  
**********
"""


class Sender_Address_Serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:

        model = Sender_Receiver_Address
        fields = ["id", "data"]

        read_only_fields = ['id']
        extra_kwargs = {
            "user_idSRAdd": {'required': False},
            'first_name': {'required': False},
            'last_name': {'required': False},
            'country_code': {'required': False},
            'phone': {'required': False},
            'address': {'required': False},
            'landmarks': {'required': False},
            'city': {'required': False},
            'pincode': {'required': False},
            'country': {'required': False},
            'latitude': {'required': False},
            'longitude': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        if not User.objects.filter(id=decrypt_datas["user_idSRAdd"]).exists():
            raise serializers.ValidationError(({"UserId": _(
                " User does not exist. ")}))

        if not decrypt_datas["first_name"].isalpha() or not decrypt_datas["last_name"].isalpha():
            raise serializers.ValidationError(({"First_Last_Name": _(
                " First Name and Last Name must be alphabet.")}))

        elif not re.match('^[+][0-9]*$', decrypt_datas["country_code"]):
            raise serializers.ValidationError(
                {"Country_Code": _("Country must be start with '+', and Numeric")})

        elif not decrypt_datas["phone"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})

        elif len(decrypt_datas["phone"]) < 8 or len(decrypt_datas["phone"]) > 12:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 12 Characters")})

        elif not decrypt_datas["city"].isalpha() or not decrypt_datas["country"].isalpha():
            raise serializers.ValidationError(
                {"City": _("City  nad Country must be Alphbet")})
        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["user_idSRAdd"] = User.objects.get(
            id=decrypt_datas["user_idSRAdd"])

        return Sender_Receiver_Address.objects.create(**decrypt_datas)

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        instance.user_idSRAdd = User.objects.get(
            id=decrypt_datas["user_idSRAdd"])

        instance.first_name = decrypt_datas['first_name']
        instance.last_name = decrypt_datas['last_name']
        instance.country_code = decrypt_datas['country_code']
        instance.address = decrypt_datas['phone']
        instance.landmarks = decrypt_datas['landmarks']
        instance.city = decrypt_datas['city']
        instance.pincode = decrypt_datas['pincode']
        instance.country = decrypt_datas['country']
        instance.latitude = decrypt_datas['latitude']
        instance.longitude = decrypt_datas['longitude']

        instance.save()

        return instance


"""
**********
    Sender  & Receiver Address Book 
**********
"""


class Sender_Receiver_Address_Book_Serializers(serializers.ModelSerializer):

    class Meta:
        model = Sender_Receiver_Address
        # fields = '__all__'
        exclude = ('created_on', 'created_by', 'updated_on', 'updated_by')


"""
**************************************************************************
                    Booking Slot 
**************************************************************************
"""


class End_BookSlot_Serializers(serializers.Serializer):

    date = serializers.DateField(format="YYYY-MM-DD",)


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


class GetPincodeDetails_serializers(serializers.ModelSerializer):
    pincode = serializers.CharField(min_length=6, max_length=7,
                                    required=True)

    class Meta:
        model = Pincode_DB
        fields = ["pincode", "Area_Name", "City", "State",
                  "Country", ]


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


class CLB_Review_for_enduser_Serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = CLB_Review
        fields = ["id", "data"]
        read_only_fields = ['id']
        extra_kwargs = {
            "review_answer": {'required': False},
            "comment": {'required': False},
            'Review_by': {'required': False},
            'created_on': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        if decrypt_datas["review_answer"] < 1 or decrypt_datas["review_answer"] > 5:
            raise serializers.ValidationError(
                {"Review": "Review Rating between 0 to 5"}
            )
        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        # decrypt_datas["user_id"] = User.objects.get(
        #     id=decrypt_datas["user_id"])

        return CLB_Review.objects.create(**decrypt_datas)


"""
********************
    Courier Compamy Review 
********************
"""


class Courier_Company_Review_for_enduser_Serializers(serializers.ModelSerializer):
    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Courier_Company_Review
        fields = ["id", "data"]
        read_only_fields = ['id']
        extra_kwargs = {
            "CC_id": {'required': False},
            "review_answer": {'required': False},
            "comment": {'required': False},
            'Review_by': {'required': False},
            'created_on': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        Courier_Data = CourierCompany.objects.filter(
            id=decrypt_datas["CC_id"]).exists()

        if not Courier_Data:
            raise serializers.ValidationError(
                {"No_Courier_Company": "Courier Company Does not exists."}
            )

        print(f"\n\n\n\n\n {Courier_Data} \n\n\n")

        if decrypt_datas["review_answer"] < 1 or decrypt_datas["review_answer"] > 5:
            raise serializers.ValidationError(
                {"Review": "Review Rating between 0 to 5"}
            )
        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])
        decrypt_datas["CC_id"] = CourierCompany.objects.get(
            id=decrypt_datas["CC_id"])

        return Courier_Company_Review.objects.create(**decrypt_datas)


"""
********************************************************************************************************************************************
                                                            Supoort Ticket 
********************************************************************************************************************************************
"""


"""
**************************
        Create Issue Ticket
**************************
"""


class SupportTicket_Encrypt_Serializres(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = Support_Ticket
        fields = ["id", "data"]
        read_only_fields = ['id', ]
        extra_kwargs = {

            'country_code': {'required': False},
            'requester_phone': {'required': False},
            'requester_email': {'required': False},
            'issue_Cate_id': {'required': False},
            'subject': {'required': False},
            'description': {'required': False},
            'order_id': {'required': False},

        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        issuseCategory_Data = Issue_Category.objects.filter(
            id=decrypt_datas["issue_Cate_id"], is_active=True).exists()

        if not issuseCategory_Data:
            raise serializers.ValidationError(
                {"No_Issuse_Category": "Issue Category Does not exists."})

        if not re.match('^[a-zA-Z0-9_+&*-]+(?:\\.[a-zA-Z0-9_+&*-]+)*@(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,7}$', decrypt_datas["requester_email"]):
            raise serializers.ValidationError(
                {'email_validation': _("Please, Enter the correct E-Mail.")})

        # Country Code
        elif not re.match('^[+][0-9]*$', decrypt_datas["country_code"]):
            raise serializers.ValidationError(
                {"Country_Code": _("Country must be start with '+', and Numeric")})

        # Phone
        # Phone Digit
        elif not decrypt_datas["requester_phone"].isdigit():
            raise serializers.ValidationError(
                {"Phonedigit": _("Phone number must be numeric")})

        # Phone Length
        elif len(decrypt_datas["requester_phone"]) < 8 or len(decrypt_datas["requester_phone"]) > 12:
            raise serializers.ValidationError(
                {"Phonelength": _("Phone must be bewtween 8  to 12 Characters")})

        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        decrypt_datas["issue_Cate_id"] = Issue_Category.objects.get(
            id=decrypt_datas["issue_Cate_id"])

        TicketNumber = CheckTicketNumber()

        while not Support_Ticket.objects.filter(ticket_no=TicketNumber):
            decrypt_datas["ticket_no"] = TicketNumber
            return Support_Ticket.objects.create(**decrypt_datas)

        else:
            TicketNumber = CheckTicketNumber()


"""
**************************
    Open-  List Issue Ticket
**************************
"""


class SupportTicket_Serializers(serializers.ModelSerializer):
    Iss_Category_name = serializers.CharField(
        source="issue_Cate_id.Catename", required=False)

    class Meta:
        model = Support_Ticket
        fields = ["id", "ticket_no",  "country_code", "requester_phone", "requester_email", "issue_Cate_id", "Iss_Category_name", "subject",
                  "description", "order_id", "is_closed", "closing_details", "closed_by", "closing_timestamp", "status", "created_on"]


"""
********************************************************************************************************************************************
                                                            Banner
********************************************************************************************************************************************
"""


class EndUser_banner_serializers(serializers.ModelSerializer):
    banner_image = Base64ImageField(use_url=True, required=False)

    class Meta:
        model = Banner
        fields = ["id", "banner_title", "banner_caption",  "banner_image"]


"""
********************************************************************************************************************************************
                                                            Offer Discount
********************************************************************************************************************************************
"""

"""
*******************
    Offer List 
*******************
"""


class EndUser_Offer_discount_serializers(serializers.ModelSerializer):

    class Meta:
        model = Offer_discount
        fields = ["id", "offer_name", "offer_description", "offer_code", "offer_minium_value",
                  "offer_amount", "offer_percentage", "offer_upto_value", "offer_start", "offer_end"]


"""
*******************
    Check Offer 
*******************
"""


class Check_Offer_Serializers(serializers.ModelSerializer):

    class Meta:
        model = Offer_discount
        fields = ['id', 'offer_code', 'offer_amount',
                  'offer_percentage', 'offer_upto_value', 'offer_start', 'offer_end']

        read_only_fields = ['id', 'offer_code', 'offer_amount',
                            'offer_percentage', 'offer_upto_value', 'offer_start', 'offer_end']


"""
********************************************************************************************************************************************
                                                            Card 
********************************************************************************************************************************************
"""


"""
***********************
    Encrypt & Decrypt Format - Card Details 
***********************
"""


class CardDetails_Encrypt_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = User_Card_Details
        fields = ["id", "data"]
        read_only_fields = ['id', ]
        extra_kwargs = {

            'UserCard_id': {'required': False},
            'Owner_name': {'required': False},
            'card_number': {'required': False},
            'exp_date': {'required': False},
        }

    def validate(self, validated_data):
        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        # User Details
        if not decrypt_datas["UserCard_id"]:
            raise serializers.ValidationError(
                {"No_User_id": "User id must be entered."})

        elif not User.objects.filter(id=decrypt_datas["UserCard_id"]).exists():
            raise serializers.ValidationError(({"UserId": _(
                " User does not exist. ")}))

        # Owner Name
        if not decrypt_datas["Owner_name"]:
            raise serializers.ValidationError(
                {"No_owener_name": "Owner name must be entered."})

        elif not re.match('^[a-zA-Z][a-zA-Z\s]*[a-zA-Z]$', decrypt_datas["Owner_name"]):
            raise serializers.ValidationError(
                {'Ownervalidation': _("Only allow Alphbet and white space.")})

        # card Number Validation
        elif not decrypt_datas["card_number"]:
            raise serializers.ValidationError(
                {"card_empy": _("Card number must be entered.")})

        elif len(decrypt_datas["card_number"]) < 8 or len(decrypt_datas["card_number"]) > 20:
            raise serializers.ValidationError(
                {"card_length": _("Card Length must be bewtween 8  to 20 Characters")})

        elif not decrypt_datas["card_number"].isdigit():
            raise serializers.ValidationError(
                {"CardDigit": _("Card number must be numeric")})

        # Expire Date

        # card Number Validation
        elif not decrypt_datas["exp_date"]:
            raise serializers.ValidationError(
                {"Card_Date": _("Card Expire Date must be entered.")})

        elif not len(decrypt_datas["exp_date"]) == 5:
            raise serializers.ValidationError(
                {"CardExp": _("Expire Date must be length of 5. ")})

        elif not re.match("(0[1-9]|1[0-2])\/[0-9]{2}", decrypt_datas["exp_date"]):
            raise serializers.ValidationError(
                {'ExpireValidation': _("Expire date must be entered 'mm/yy' ")})

        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        decrypt_datas["UserCard_id"] = User.objects.get(
            id=decrypt_datas["UserCard_id"])

        return User_Card_Details.objects.create(**decrypt_datas)

    def update(self, instance, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        instance.UserCard_id = User.objects.get(
            id=decrypt_datas["UserCard_id"])

        instance.Owner_name = decrypt_datas['Owner_name']
        instance.card_number = decrypt_datas['card_number']
        instance.exp_date = decrypt_datas['exp_date']

        instance.save()

        return instance


"""
***********************
    Normal - Card Details 
***********************
"""


class CardDetails_Serializers(serializers.ModelSerializer):

    class Meta:
        model = User_Card_Details
        fields = ["id", "UserCard_id", "Owner_name", "card_number", "exp_date"]
        read_only_fields = ['id', ]


"""
********************************************************************************************************************************************
                                                            End User Orders 
********************************************************************************************************************************************
"""


"""
***********************
    Encrypt & Decrypt Format - Order Details 
***********************
"""


class End_User_Order_Encrypt_Serializers(serializers.ModelSerializer):

    data = serializers.CharField(min_length=6, max_length=1500,
                                 write_only=True, required=True, )

    class Meta:
        model = End_User_Order
        fields = ["id", "data"]
        read_only_fields = ['id', ]
        extra_kwargs = {

            'booking_order_id': {'required': False},
            'company_name_id': {'required': False},
            'awb_no': {'required': False},
            'user_idEndOrder': {'required': False},
            'Sender_id': {'required': False},
            'Receiver_id': {'required': False},
            'origin': {'required': False},
            'destination': {'required': False},
            'ServiceType': {'required': False},
            'ShipmentType': {'required': False},
            'TravelBy': {'required': False},
            'content_of_shipment': {'required': False},
            'value_of_goods': {'required': False},
            'weight': {'required': False},
            'dimension': {'required': False},
            'volumetric_weight': {'required': False},
            'texable_value': {'required': False},
            'sgst': {'required': False},
            'cgst': {'required': False},
            'pickup_charge': {'required': False},
            'totalcharge': {'required': False},
            'booking_tnc': {'required': False},
            'eway_bill_no': {'required': False},
            'eway_bill_date': {'required': False},
            'endUser_gstNo': {'required': False},
        }

    def validate(self, validated_data):

        data = validated_data.get("data")
        decrypt_datas = Json_decrypt_data(data)

        # Empty Courier Company
        if not decrypt_datas["company_name_id"]:
            raise serializers.ValidationError(
                {'no_Courier': _("Courier compnay must be enterd.")})

        # No user id
        elif not decrypt_datas["user_idEndOrder"]:
            raise serializers.ValidationError(
                {"no_user": _("User id must be entered.")})

        # No Sender
        elif not decrypt_datas["Sender_id"]:
            raise serializers.ValidationError(
                {"no_Sender": _("Sender id must be entered.")})

        # No Receiver
        elif not decrypt_datas["Receiver_id"]:
            raise serializers.ValidationError(
                {"no_receiver": _("Receiver id must be entered.")})

        # No origin
        elif not decrypt_datas["origin"]:
            raise serializers.ValidationError(
                {"no_origin": _("origin must be entered.")})

        # No destination
        elif not decrypt_datas["destination"]:
            raise serializers.ValidationError(
                {"no_destination": _("destination  must be entered.")})

        # No ServiceType
        elif not decrypt_datas["ServiceType"]:
            raise serializers.ValidationError(
                {"no_service": _("Service Type must be entered.")})

        # No ShipmentType
        elif not decrypt_datas["ShipmentType"]:
            raise serializers.ValidationError(
                {"no_shipment": _("Shipment Type must be entered.")})

        # No TravelBy
        elif not decrypt_datas["TravelBy"]:
            raise serializers.ValidationError(
                {"no_Travel": _("Travel By must be entered.")})

        # No content_of_shipment
        elif not decrypt_datas["content_of_shipment"]:
            raise serializers.ValidationError(
                {"no_content": _("content of shipment must be entered.")})

        # No value_of_goods
        elif not decrypt_datas["value_of_goods"]:
            raise serializers.ValidationError(
                {"no_value": _("value of goods must be entered.")})

        # No weight
        elif not decrypt_datas["weight"]:
            raise serializers.ValidationError(
                {"no_weight": _("weight must be entered.")})

        # No texable_value
        elif not decrypt_datas["texable_value"]:
            raise serializers.ValidationError(
                {"no_taxeble": _("Texable value must be entered.")})

        # No sgst
        elif not decrypt_datas["sgst"]:
            raise serializers.ValidationError(
                {"no_sgst": _("SGST must be entered.")})

        # No cgst
        elif not decrypt_datas["cgst"]:
            raise serializers.ValidationError(
                {"no_cgst": _("CGST must be entered.")})

        # No pickup_charge
        elif not decrypt_datas["pickup_charge"]:
            raise serializers.ValidationError(
                {"no_pickup": _("Pickup charge must be entered.")})

        # No totalcharge
        elif not decrypt_datas["totalcharge"]:
            raise serializers.ValidationError(
                {"no_totalcharge": _("Total charge must be entered.")})

        print("\n\n\n\n hello Exist \n\n\n")
        # Check Courier Company
        ExistCourier_Data = CourierCompany.objects.filter(
            id=decrypt_datas["company_name_id"], is_active=True).exists()

        # Check User
        ExistUserId_Data = User.objects.filter(
            id=decrypt_datas["user_idEndOrder"], is_active=True, user_type="EndUser").exists()

        # Check Sender Address
        ExistSenderAddress_Data = Sender_Receiver_Address.objects.filter(
            id=decrypt_datas["Sender_id"], is_active=True, user_idSRAdd__is_active=True,  user_idSRAdd__user_type="EndUser").exists()

        # Check Receiver Address
        ExistReceiverAddress_Data = Sender_Receiver_Address.objects.filter(
            id=decrypt_datas["Receiver_id"], is_active=True, user_idSRAdd__is_active=True, user_idSRAdd__user_type="EndUser").exists()

        # Exist Data
        if not ExistCourier_Data:
            raise serializers.ValidationError(
                {"Exist_Courier": "Courier does not exists."})

        if not ExistUserId_Data:
            raise serializers.ValidationError(
                {"Exist_User": "User does not exists."})

        if not ExistSenderAddress_Data:
            raise serializers.ValidationError(
                {"Exist_Sender_address": "Sender address does not exists."})

        if not ExistReceiverAddress_Data:
            raise serializers.ValidationError(
                {"Exist_Receiver_address": "Receiver address does not exists."})

        # ServiceType not in list
        if decrypt_datas["ServiceType"].capitalize() not in ["Standard", "Priority"]:
            raise serializers.ValidationError(
                {"Check_Service_type": _("Service Type must be entered Standard or Priority")})

        # ShipmentType not in list
        elif decrypt_datas["ShipmentType"].capitalize() not in ["Documents", "Parcel"]:
            raise serializers.ValidationError(
                {"Check_Shipment_type": _("Shipment Type must be entered Documents or Parcel ")})

        # TravelBy not in list
        elif decrypt_datas["TravelBy"].capitalize() not in ["Air", "Surface", "Air/Surface"]:
            raise serializers.ValidationError(
                {"Check_Travel_by": _("Travel by must be entered Air or Surface or Air/Surface.")})

        # Check type value_of_goods == Int
        elif type(decrypt_datas["value_of_goods"]) != int:
            raise serializers.ValidationError(
                {"check_value_type": _("Value of good must be entered intger number.")})

        # Check type value_of_goods < Int
        elif decrypt_datas["value_of_goods"] < 0:
            raise serializers.ValidationError(
                {"check_value_0": _("Invalid value of goods, Please Enter correct value")})

        # Check type wight == Int
        elif type(decrypt_datas["weight"]) != int:
            raise serializers.ValidationError(
                {"check_weight_type": _("Weight must be entered intger (grams) number.")})

        # Check type value_of_goods < Int
        elif decrypt_datas["weight"] < 0:
            raise serializers.ValidationError(
                {"check_weight_0": _("Invalid Weight, Please Enter correct weight")})

        # dimension
        if decrypt_datas["ShipmentType"].capitalize() == "Parcel":
            if decrypt_datas["ShipmentType"].capitalize() != "Parcel":
                raise serializers.ValidationError(
                    {"no_parcel": _("Shipment type must be entered Parcel.")})

            elif not decrypt_datas["dimension"]:
                raise serializers.ValidationError(
                    {"no_dimension": _("Dimension must be entered.")})

            elif not decrypt_datas["volumetric_weight"]:
                raise serializers.ValidationError(
                    {"no_volumetric_weight": _("Volumetric weight must be entered.")})

        # Taxable
        if type(decrypt_datas["texable_value"]) != float:
            raise serializers.ValidationError(
                {"check_taxable_amt_type": _("Taxable value must be entered decimal number (000.00).")})

        elif decrypt_datas["texable_value"] < 0:
            raise serializers.ValidationError(
                {"check_taxable_0": _("Invalid Taxable amount, Please Enter correct Taxable amount")})

        # GST
        if decrypt_datas["sgst"] < 0:
            raise serializers.ValidationError(
                {"check_sgst_0": _("Invalid SGST amount, Please Enter correct SGST amount")})

        elif decrypt_datas["cgst"] < 0:
            raise serializers.ValidationError(
                {"check_cgst_0": _("Invalid CGST amount, Please Enter correct CGST amount")})

        # PickUp Charge
        if type(decrypt_datas["pickup_charge"]) != int:
            raise serializers.ValidationError(
                {"check_pickup_charge_type": _("PickUp charge must be entered Intget number.")})

        elif decrypt_datas["pickup_charge"] < 0:
            raise serializers.ValidationError(
                {"check_pickup_charge_0": _("Invalid PickUp charge, Please Enter correct PickUp charge.")})

        # Total Charge
        elif decrypt_datas["totalcharge"] < 0:
            raise serializers.ValidationError(
                {"check_totalcharge_0": _("Invalid Total charge, Please Enter correct Total charge.")})

        # Booking Term and Condition
        if "booking_tnc" not in decrypt_datas:
            raise serializers.ValidationError(
                {"No_booking_tnc": _("Booking tnc must be entered.")})

        elif decrypt_datas["booking_tnc"] == False:
            raise serializers.ValidationError(
                {"false_booking_tnc": _("Booking tnc must be True.")})

        # e-way Bill
        if decrypt_datas["value_of_goods"] > 49998:

            if not decrypt_datas["eway_bill_no"]:
                raise serializers.ValidationError(
                    {"no_eway_bill_no": _("Eway bill number must be entered.")})

            elif not decrypt_datas["eway_bill_date"]:
                raise serializers.ValidationError(
                    {"no_volumetric_weight": _("Eway bill date must be entered.")})

            if not decrypt_datas["eway_bill_no"].isdigit():
                raise serializers.ValidationError(
                    {"Check_eway_bill_number": _("Eway bill date must be entered in numeric.")})

        print("\n\n\n\n hello \n\n\n")

        return validated_data

    def create(self, validated_data):
        decrypt_datas = Json_decrypt_data(validated_data["data"])

        decrypt_datas["company_name_id"] = CourierCompany.objects.get(
            id=decrypt_datas["company_name_id"])

        decrypt_datas["user_idEndOrder"] = User.objects.get(
            id=decrypt_datas["user_idEndOrder"])

        decrypt_datas["Sender_id"] = Sender_Receiver_Address.objects.get(
            id=decrypt_datas["Sender_id"])

        decrypt_datas["Receiver_id"] = Sender_Receiver_Address.objects.get(
            id=decrypt_datas["Receiver_id"])

        OrderNumber = Check_And_Generate_Order_Number()

        while not End_User_Order.objects.filter(booking_order_id=OrderNumber):
            decrypt_datas["booking_order_id"] = OrderNumber
            return End_User_Order.objects.create(**decrypt_datas)

        else:
            OrderNumber = Check_And_Generate_Order_Number()


"""
***********************
    Encrypt & Decrypt Format - Card Details 
***********************
"""


class EndUser_Order_Serializers(serializers.ModelSerializer):
    courier_Company_Name = serializers.CharField(
        source="company_name_id.name", required=False)

    user_name = serializers.CharField(
        source="user_idEndOrder.first_name", required=False)

    Sender_id = Sender_Receiver_Address_Book_Serializers(read_only=True)
    Receiver_id = Sender_Receiver_Address_Book_Serializers(
        read_only=True)

    class Meta:
        model = End_User_Order
        fields = ["id", "order_date", "booking_order_id", "company_name_id", "courier_Company_Name", "user_idEndOrder", "user_name",
                  "Sender_id", "Receiver_id", "origin", "destination", "ServiceType", "ShipmentType", "TravelBy", "content_of_shipment", "value_of_goods", "weight",  "dimension", "volumetric_weight", "texable_value", "sgst", "cgst", "pickup_charge", "totalcharge", "booking_tnc", "eway_bill_no", "eway_bill_date", "endUser_gstNo"
                  ]
