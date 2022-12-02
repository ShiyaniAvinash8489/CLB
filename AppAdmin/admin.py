"""
*************************************
        Imported Packages
*************************************
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin


# Models
from AppAdmin.models import (
    # Custom User Model
    User,

    # System Log
    SystemAndDeviceLog,

    # Indian Pincode
    Pincode_DB,

    # Booking Slot
    BookingSlot,

    # CLB -Review
    CLB_Review,
    Courier_Company_Review,

    # Courier Company
    CourierCompany,

    # Price
    PriceForCustomer,
    Our_Price,

    # FAQ
    FAQ_Cateogry,
    FAQ,

    # Contact us
    ContactUs,


    # Ticket Support
    Issue_Category,
    Support_Ticket,

    # Notification
    Notification,

    # Banner
    Banner,

    # Offer_Discount
    Offer_discount,
)


"""
**************************************************************************
                                Set Up Admin
**************************************************************************
"""


"""
*************
    User
*************
"""


# User Admin
@admin.register(User)
class UserAdmin(UserAdmin):
    list_display = ['id', 'first_name', 'last_name',
                    'phone', 'is_active', 'user_type']

    # list_filter = ['is_active', 'is_staff', ]

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        ("Register Info:", {"fields": ("id", "email",
         "username", "country_code", "phone", "password")}),
        ("Personal Info", {
         "fields": ("first_name", "last_name", "profile_images"), },),
        ("User Type", {"fields": ("user_type",), },),
        ("Location", {"fields": ("latitude", "longitude"), },),
        ("Other Info", {"fields": ("auth_provider",), },),
        ("Login Info", {"fields": ("last_login",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
        ("Permissions", {"fields": ("user_permissions", "groups"), },),
        ("Admin Login", {"fields": ("is_active", "is_superuser",
         "is_staff", "is_verify", "user_tnc",), },),
    )


"""
*************
    SystemAndDeviceLog
*************
"""


@admin.register(SystemAndDeviceLog)
class SystemAndDeviceLog_Admin(admin.ModelAdmin):
    list_display = ["id", "user_idSysLog", "device_type", "active_fcm"]

    readonly_fields = ["id", "date_time"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Active Log   Details:", {"fields": ("user_idSysLog", "date_time", "os_type",
         "os_version", "device_type", "device_id", "browser", "brower_version", "fcm_token", "active_fcm")},),
    )


"""
*************
    Pincode
*************
"""


@admin.register(Pincode_DB)
class Pincode_Admin(admin.ModelAdmin):
    list_display = ["id", "CC_Pin_id", "pincode", "City",
                    "State", "is_clb_pickup", "is_delivery", "is_active"]

    readonly_fields = ["id", "created_on",
                       "created_by", "updated_on", "updated_by"]

    fieldsets = (
        ("Registry:", {"fields": ("id",)},),
        ("Courier Company:", {"fields": ("CC_Pin_id",)},),
        ("Pincode Details:", {
         "fields": ("pincode", "Area_Name", "City", "State", "Country",)},),
        ("Active ", {"fields": ("is_clb_pickup",
                                "is_delivery", "is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*************
    Booking Slot 
*************
"""


@admin.register(BookingSlot)
class Booking_Slot_Admin(admin.ModelAdmin):
    list_display = ["id", "start_time", "end_time",
                    "allow_time_after_start_time", "is_active"]

    readonly_fields = ["id", "created_on",
                       "created_by", "updated_on", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Booking Slot Time:", {"fields": ("start_time",
         "end_time", "allow_time_after_start_time")},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*************
    Courier Company 
*************
"""


@admin.register(CourierCompany)
class Courier_Company_Admin(admin.ModelAdmin):
    list_display = ["id", "name", "is_active", ]

    readonly_fields = ["id", "created_on",
                       "created_by", "updated_on", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Company Name & Address:", {"fields": ("name", "logo", "address",)},),
        ("Tax Details :", {
         "fields": ("GST_number", "GST_Img", "PanCard_number",)},),
        ("Contact Details :", {
         "fields": ("contact_person_name", "contact_number", "email", "website")},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*************
    CLB - Review 
*************
"""


@admin.register(CLB_Review)
class CLB_Review_Admin(admin.ModelAdmin):
    list_display = ["id", "review_answer", "Review_by"]

    readonly_fields = ["id", "created_on"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Rating:", {"fields": ("review_answer",)},),
        ("Comment:", {"fields": ("Review_by", "comment")},),
        ("TimeStamp ", {"fields": ("created_on",), },),
    )


"""
*************
    CLB - Review 
*************
"""


@admin.register(Courier_Company_Review)
class Courier_Company_Review_Admin(admin.ModelAdmin):
    list_display = ["id", "CC_id", "review_answer", "Review_User"]

    readonly_fields = ["id", "created_on"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Company Name:", {"fields": ("CC_id",)},),
        ("Rating:", {"fields": ("review_answer",)},),
        ("Comment:", {"fields": ("Review_User", "comment")},),
        ("TimeStamp ", {"fields": ("created_on",), },),
    )


"""
*************
    Price for Customer 
*************
"""


@admin.register(PriceForCustomer)
class Price_For_Customer_Admin(admin.ModelAdmin):
    list_display = ["id", "CC_Price_id",
                    "ServiceType", "ShipmentType", "TravelBy"]

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Company Name:", {"fields": ("CC_Price_id",)},),
        ("Types:", {"fields": ("ServiceType", "ShipmentType", "TravelBy", )},),
        ("Weight:", {"fields": ("Weight_From", "Weight_To")},),
        ("Price:", {"fields": ("Local", "State", "RestOfIndia")},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*************
    Our Price
*************
"""


@admin.register(Our_Price)
class Our_Price_Admin(admin.ModelAdmin):
    list_display = ["id", "CC_OurPrice_id",
                    "ServiceType", "ShipmentType", "TravelBy"]

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Company Name:", {"fields": ("CC_OurPrice_id",)},),
        ("Types:", {"fields": ("ServiceType", "ShipmentType", "TravelBy", )},),
        ("Weight:", {"fields": ("Weight_From", "Weight_To")},),
        ("Price:", {"fields": ("Local", "State", "RestOfIndia")},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    FAQ Category 
*******************
"""


@admin.register(FAQ_Cateogry)
class FAQ_CateogryAdmin(admin.ModelAdmin):
    list_display = ["id", "name", "is_active"]

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Category:", {"fields": ("name",)},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    FAQ 
*******************
"""


@admin.register(FAQ)
class FAQ_Admin(admin.ModelAdmin):
    list_display = ["id", "faq_category_id",
                    "question", "answer", "is_active"]

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Category:", {"fields": ("faq_category_id",)},),
        ("FAQ:", {"fields": ("question", "answer",)},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    Contact Us 
*******************
"""


@admin.register(ContactUs)
class ContactUs_Admin(admin.ModelAdmin):
    list_display = ["id", "name",
                    "phone", "email", "subject", "is_solve", "is_active", ]

    readonly_fields = ["id", "solve_timeshtamp", "solve_by", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Person Details:", {"fields": ("name", "phone", "email",)},),
        ("Details:", {"fields": ("subject", "description",)},),

        ("Solve:", {"fields": ("is_solve", "solve_timeshtamp", "solve_by")},),

        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    Issue Category 
*******************
"""


@admin.register(Issue_Category)
class Issue_Cateogry_Admin(admin.ModelAdmin):
    list_display = ["id", "Catename", "is_active"]

    readonly_fields = ["id", "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Category:", {"fields": ("Catename",)},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    Support Ticket
*******************
"""


@admin.register(Support_Ticket)
class Support_Ticket_Admin(admin.ModelAdmin):
    list_display = ["id", "ticket_no", "client_User_Id",
                    "issue_Cate_id", "is_closed", "status", "is_active"]

    readonly_fields = ["id", "closed_by", "closing_timestamp",  "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("User Details:", {"fields": (
            "client_User_Id", "country_code", "requester_phone", "requester_email")},),

        ("Ticket Details:", {"fields": ("ticket_no", "issue_Cate_id",
         "subject",   "description", "order_id",)},),

        ("Support Team:", {"fields": (
            "status", "is_closed", "closing_details", "closed_by", "closing_timestamp")},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    Notification
*******************
"""


@admin.register(Notification)
class Notification_Admin(admin.ModelAdmin):
    list_display = ["id", "title",  "is_active"]

    readonly_fields = ["id",  "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Notification:", {
         "fields": ("usersType", "title", "body", "Notif_image", )},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    Banner 
*******************
"""


@admin.register(Banner)
class Banner_Admin(admin.ModelAdmin):
    list_display = ["id", "banner_title",
                    "banner_start", "banner_end", "is_active"]

    readonly_fields = ["id",  "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Banner:", {
         "fields": ("banner_title", "banner_caption", "banner_image", "banner_start", "banner_end")},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )


"""
*******************
    Offer Discount 
*******************
"""


@admin.register(Offer_discount)
class Offer_discount_Admin(admin.ModelAdmin):
    list_display = ["id", "offer_name",
                    "offer_start", "offer_end", "is_active"]

    readonly_fields = ["id",  "created_on",
                       "updated_on", "created_by", "updated_by"]

    fieldsets = (
        # Id Informations
        ("Registry:", {"fields": ("id",)},),
        ("Offer Name:", {
         "fields": ("offer_name", "offer_description",)},),
        ("Offer Code:", {"fields": ("offer_code", )},),

        ("Offer Amount:", {"fields": ("offer_amount",)},),
        ("Offer Percentage:", {
         "fields": ("offer_percentage", "offer_upto_value", )},),
        ("Offer Minium Value:", {"fields": ("offer_minium_value", )},),
        ("Offer Period:", {"fields": ("offer_start", "offer_end")},),
        ("Active ", {"fields": ("is_active",), },),
        ("Time Stamp Info", {"fields": ("created_on",
         "created_by", "updated_on", "updated_by"), },),
    )
