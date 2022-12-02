"""
*************************************
        Imported Packages
*************************************
"""

from django.contrib import admin


# Models
from AppAgent.models import (
    Agent_Address,
    Agent_Bank_Details,
    Agent_KYC,
    Agent_Verify_Email_Mobile,

)


"""
**************************************************************************
                                Set Up Admin
**************************************************************************
"""


"""
*************
    Agent Address
*************
"""


@admin.register(Agent_Address)
class Agent_Address_Admin(admin.ModelAdmin):
    list_display = ["id", "user_idAddress",
                    "city", "state", "country", "is_active"]

    readonly_fields = ["id", "created_on",
                       "created_by", "updated_on", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("User:", {"fields": ("user_idAddress",)},),
        ("Address:", {"fields": ("address_line_1", "address_line_2", "landmarks", "city",
                                 "state", "pincode", "country")},),

        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*************
    Agent Bank Details 
*************
"""


@admin.register(Agent_Bank_Details)
class Agent_Bank_Details_Admin(admin.ModelAdmin):
    list_display = ["id", "user_idBank", "bank_name",
                    "branch_name", "is_verify", "is_active"]

    readonly_fields = ["id", "created_on",
                       "created_by", "updated_on", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("User:", {"fields": ("user_idBank",)},),
        ("Bank Details:", {"fields": ("bank_name", "branch_name", "IFSC_code", "account_number",
                                      "cancel_cheque")},),
        ("Active ", {"fields": ("is_verify", "is_verify_by", "is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*************
     Agent KYC
*************
"""


@admin.register(Agent_KYC)
class Agent_KYC_Admin(admin.ModelAdmin):
    list_display = ["id", "user_idKYC", "KYC_Name", "is_verify", "is_active"]

    readonly_fields = ["id", "created_on",
                       "created_by", "updated_on", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("User:", {"fields": ("user_idKYC", "UserKYCImage")},),
        ("KYC:", {"fields": ("KYC_Name", "frontside_image", "backside_image",)},),
        ("Active ", {"fields": ("is_verify", "is_verify_by", "is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*************
     Verify Email & Mobile 
*************
"""


@admin.register(Agent_Verify_Email_Mobile)
class Agent_VerifyEmailPhone_Admin(admin.ModelAdmin):
    list_display = ["id", "email", "is_verify_email", "otp", "is_verify",
                    "phone", "is_verify_phone"]

    # readonly_fields = ["id", "email",
    #                    "is_verify_email", "country_code", "phone", "is_verify_phone", "gen_datetime"]
    readonly_fields = ["id", "gen_datetime"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),

        ("Email:", {"fields": ("email", "is_verify_email",)},),
        ("OTP:", {"fields": ("otp", "gen_datetime", "exp_datetime", "is_verify")},),

        ("Phone ", {"fields": ("country_code", "phone", "is_verify_phone"), },),

    )
