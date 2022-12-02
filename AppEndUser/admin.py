"""
*************************************
        Imported Packages 
*************************************
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin


# # Models
from AppEndUser.models import (
    Sender_Receiver_Address,
    User_Card_Details,
    End_User_Order,

)


"""
**************************************************************************
                                Set Up Admin  
**************************************************************************
"""


"""
*************
    End-User Address  
*************
"""


@admin.register(Sender_Receiver_Address)
class Sender_Receiver_Address_Admin(admin.ModelAdmin):
    list_display = ["id", "user_idSRAdd",
                    "first_name", "last_name", 'is_active']

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        ("Registry:", {"fields": ("id",)},),
        ("Address  Details:", {"fields": ("user_idSRAdd", "first_name", "last_name",
         "country_code", "phone", "address", "landmarks", "city", "pincode", "country",)},),
        ("Location  Details:", {"fields": ("latitude", "longitude",)},),
        ("Active:", {"fields": ("is_active",)},),
        ("Time Stamp Info", {"fields": ("created_on", "created_by", "updated_on", "updated_by"), },),)


"""
*************
    End-User Card Details 
*************
"""


@admin.register(User_Card_Details)
class EndUser_Card_Details_Admin(admin.ModelAdmin):
    list_display = ["id", "UserCard_id",
                    "Owner_name", 'is_active']

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        ("Registry:", {"fields": ("id",)},),
        ("User  Details:", {"fields": ("UserCard_id", )},),
        ("Card  Details:", {
         "fields": ("Owner_name", "card_number", "exp_date")},),
        ("Active:", {"fields": ("is_active",)},),
        ("Time Stamp Info", {"fields": ("created_on", "created_by", "updated_on", "updated_by"), },),)


"""
*************
    End-User Card Details 
*************
"""


@admin.register(End_User_Order)
class End_User_Order_Admin(admin.ModelAdmin):
    list_display = ["id", "order_date",
                    "booking_order_id", "user_idEndOrder", "totalcharge", 'is_active']

    readonly_fields = ["id", "order_date", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        ("Registry:", {"fields": ("id",)},),
        ("Order Details:", {"fields": ("order_date", "booking_order_id", )},),
        ("Company Details:", {"fields": ("company_name_id", "awb_no")},),
        ("Booking User:", {"fields": ("user_idEndOrder", )},),
        ("Booking Details:", {"fields": ("Sender_id", "Receiver_id", "origin",
         "destination",)},),

        ("Type Details:", {
         "fields": ("ServiceType", "ShipmentType", "TravelBy")},),
        ("Shipment Details:", {
         "fields": ("content_of_shipment", "value_of_goods",)},),

        ("Weight Details:", {
         "fields": ("weight", "dimension", "volumetric_weight")},),

        ("Value Details:", {
         "fields": ("texable_value", "sgst", "cgst", "pickup_charge", "totalcharge")},),


        ("E-Bill Details:",
         {"fields": ("eway_bill_no", "eway_bill_date", "endUser_gstNo")},),

        ("Active & Term & Condition:", {
         "fields": ("is_active", "booking_tnc")},),
        ("Time Stamp Info", {"fields": ("created_on", "created_by", "updated_on", "updated_by"), },),)
