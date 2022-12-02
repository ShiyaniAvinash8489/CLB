"""
*************************************
        Imported Packages
*************************************
"""

# By Default
from enum import unique
from django.db import models

# Custom User
from django.contrib.auth.models import AbstractUser, AnonymousUser

# Import UserManager Model
from AppAdmin.UserManager import UserManager

# JWT
from rest_framework_simplejwt.tokens import RefreshToken

# Translations
from django.utils.translation import gettext_lazy as _


"""
**************************************************************************
                            Create Your models here
**************************************************************************
"""


"""
*************************************
        Custom User Models
*************************************
"""


AUTH_PROVIDERS = {'email': 'email'}


# Custom User
class User(AbstractUser):

    UserType = [
        ("EndUser", "EndUser"),
        ("Admin", "Admin"),
        ("Agent", "Agent"),
    ]

    # Personal Details and Address , Username, Password

    first_name = models.CharField(max_length=150, null=True,
                                  blank=True)
    middle_name = models.CharField(max_length=150, null=True,
                                   blank=True,)
    last_name = models.CharField(max_length=150, null=True,
                                 blank=True)
    username = models.CharField(max_length=50, unique=True, null=True,
                                blank=True)

    country_code = models.CharField(max_length=50)
    phone = models.CharField(max_length=20, unique=True)
    email = models.EmailField(max_length=254, unique=True,
                              null=True, blank=True)

    password = models.CharField(max_length=100, null=True, blank=True)

    # User Type
    user_type = models.CharField(max_length=50, choices=UserType,
                                 default="EndUser")

    # Location
    latitude = models.CharField(max_length=100, null=True, blank=True)
    longitude = models.CharField(max_length=100, null=True, blank=True)

    # Auth Provide
    auth_provider = models.CharField(max_length=255, blank=False, null=False,
                                     default=AUTH_PROVIDERS.get('email'))

    # Verify Account
    is_active = models.BooleanField(default=False)
    is_verify = models.BooleanField(default=False)
    user_tnc = models.BooleanField(default=False)

    # Admin
    is_staff = models.BooleanField(default=False)

    # Imp Fields
    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    # Images
    profile_images = models.ImageField(
        upload_to='user_profile', null=True, max_length=100)

    # Username & Required Fields
    USERNAME_FIELD = 'phone'
    REQUIRED_FIELDS = ["email", 'username']

    # Import Module of UserMagers.py
    objects = UserManager()

    def __unicode__(self):
        return self.id

    def __str__(self):
        name = (f"{self.username} {self.phone}")
        return (name)
        # return f'{self.review_category} ({self.review_question})'

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {"refresh": str(refresh), "access": str(refresh.access_token)}


"""
**************************************************************************
                                Management
**************************************************************************
"""


"""
*************************************
        Device & System  Log
*************************************
"""


class SystemAndDeviceLog(models.Model):
    user_idSysLog = models.ForeignKey(User, on_delete=models.CASCADE,
                                      related_query_name='SDLUserID',
                                      limit_choices_to={
                                          'is_active': True, },
                                      null=True, blank=True)

    date_time = models.DateTimeField(auto_now_add=True)

    # os - Windows or linux
    os_type = models.CharField(max_length=100, null=True, blank=True)
    os_version = models.CharField(max_length=100, null=True, blank=True)

    # device = device id
    device_id = models.CharField(max_length=100, null=True, blank=True)

    # device type = android / ios
    device_type = models.CharField(max_length=100, default="None", choices=[
                                   ("android", "android"), ("ios", "ios"), ("None", "None"), ])

    # FCM
    fcm_token = models.CharField(max_length=200, null=True, blank=True)
    active_fcm = models.BooleanField(default=True)

    browser = models.CharField(max_length=100, null=True, blank=True)
    brower_version = models.CharField(max_length=100, null=True, blank=True)


"""
****************************************************************************************************************************************************
                                                            Booking Slot
****************************************************************************************************************************************************
"""


class BookingSlot(models.Model):

    start_time = models.TimeField()
    end_time = models.TimeField()
    allow_time_after_start_time = models.TimeField()

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        time = f"{str(self.start_time)} To {str(self.end_time)}"
        return time


"""
****************************************************************************************************************************************************
                                                            Courier Company 
****************************************************************************************************************************************************
"""


class CourierCompany(models.Model):

    name = models.CharField(max_length=100)
    logo = models.ImageField(upload_to="CourierLogo", null=True, blank=True)
    address = models.TextField(max_length=256, null=True, blank=True)
    GST_number = models.CharField(
        max_length=50, null=True, blank=True, unique=True)
    GST_Img = models.ImageField(upload_to="CourierGST", null=True, blank=True)
    PanCard_number = models.CharField(
        max_length=12, null=True, blank=True, unique=True)
    contact_person_name = models.CharField(
        max_length=50, null=True, blank=True)
    contact_number = models.CharField(max_length=50, null=True, blank=True)
    email = models.EmailField(
        max_length=254, null=True, blank=True, unique=True)
    website = models.URLField(
        max_length=200, null=True, blank=True, unique=True)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):

        return self.name


"""
****************************************************************************************************************************************************
                                                                Pincode
****************************************************************************************************************************************************
"""


class Pincode_DB(models.Model):
    CC_Pin_id = models.ForeignKey(CourierCompany, on_delete=models.CASCADE,
                                  related_name='PincodeCCIds',
                                  related_query_name='PincodeCCId',
                                  limit_choices_to={'is_active': True},)

    pincode = models.CharField(max_length=8)
    Area_Name = models.CharField(max_length=100, blank=True, null=True)
    City = models.CharField(max_length=100, blank=True, null=True)
    State = models.CharField(max_length=100, blank=True, null=True)
    Country = models.CharField(max_length=100, blank=True, null=True)

    is_clb_pickup = models.BooleanField(default=True)
    is_delivery = models.BooleanField(default=True)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)


"""
****************************************************************************************************************************************************
                                                                CLB - Review 
****************************************************************************************************************************************************
"""


"""
*******************
    CLB Review 
*******************
"""


class CLB_Review(models.Model):
    Review_Answer = [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (5, 5)
    ]

    review_answer = models.IntegerField(choices=Review_Answer, default=0)
    comment = models.TextField(max_length=1000, null=True, blank=True)

    Review_by = models.ForeignKey(User, on_delete=models.CASCADE,
                                  related_query_name='ReviewUserID',
                                  limit_choices_to={
                                      'is_active': True, 'user_type': 'EndUser'},
                                  null=True, blank=True)

    created_on = models.DateTimeField(auto_now_add=True)


"""
*******************
    Courier Company Reviews 
*******************
"""


class Courier_Company_Review(models.Model):
    Review_Answer = [
        (0, 0),
        (1, 1),
        (2, 2),
        (3, 3),
        (4, 4),
        (5, 5)
    ]
    CC_id = models.ForeignKey(CourierCompany, on_delete=models.CASCADE,
                              related_name='ReviewCCIds',
                              related_query_name='ReviewCCId',
                              limit_choices_to={'is_active': True},)

    review_answer = models.IntegerField(choices=Review_Answer, default=0)
    comment = models.TextField(max_length=1000, null=True, blank=True)

    Review_User = models.ForeignKey(User, on_delete=models.CASCADE,
                                    related_query_name='ReviewByUserID',
                                    limit_choices_to={
                                        'is_active': True, 'user_type': 'EndUser'},
                                    null=True, blank=True)

    created_on = models.DateTimeField(auto_now_add=True)


"""
****************************************************************************************************************************************************
                                                            Courier Company Price 
****************************************************************************************************************************************************
"""


"""
*******************
    Price for Customer 
*******************
"""


class PriceForCustomer(models.Model):

    ServiceType_Choice = [
        ("Standard", "Standard"),
        ("Priority", "Priority"),
    ]

    ShipmentType_Choice = [
        ("Documents", "Documents"),
        ("Parcel", "Parcel"),
    ]

    TravelType_Choice = [
        ("Air", "Air"),
        ("Surface", "Surface"),
        ("Air/Surface", "Air/Surface"),
    ]

    CC_Price_id = models.ForeignKey(CourierCompany, on_delete=models.CASCADE,
                                    related_name='PriceCCIds',
                                    related_query_name='PriceCCId',
                                    limit_choices_to={'is_active': True},)

    ServiceType = models.CharField(max_length=50, choices=ServiceType_Choice,
                                   default="Standard")
    ShipmentType = models.CharField(max_length=50, choices=ShipmentType_Choice,
                                    default="Documents")
    TravelBy = models.CharField(max_length=50, choices=TravelType_Choice,
                                default="Air/Surface")
    Weight_From = models.IntegerField()
    Weight_To = models.IntegerField()
    Local = models.IntegerField()
    State = models.IntegerField()
    RestOfIndia = models.IntegerField()

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):

        return self.ServiceType


"""
*******************
    Price Us
*******************
"""


class Our_Price(models.Model):

    ServiceType_Choice = [
        ("Standard", "Standard"),
        ("Priority", "Priority"),
    ]

    ShipmentType_Choice = [
        ("Documents", "Documents"),
        ("Parcel", "Parcel"),
    ]

    TravelType_Choice = [
        ("Air", "Air"),
        ("Surface", "Surface"),
    ]

    CC_OurPrice_id = models.ForeignKey(CourierCompany, on_delete=models.CASCADE,
                                       related_name='OurPriceCCIds',
                                       related_query_name='OurPriceCCId',
                                       limit_choices_to={'is_active': True},)

    ServiceType = models.CharField(max_length=50, choices=ServiceType_Choice,
                                   default="Standard")
    ShipmentType = models.CharField(max_length=50, choices=ShipmentType_Choice,
                                    default="Documents")
    TravelBy = models.CharField(max_length=50, choices=TravelType_Choice,
                                default="Surface")
    Weight_From = models.IntegerField()
    Weight_To = models.IntegerField()
    Local = models.IntegerField()
    State = models.IntegerField()
    RestOfIndia = models.IntegerField()

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):

        return self.ServiceType


"""
****************************************************************************************************************************************************
                                                                FAQ 
****************************************************************************************************************************************************
"""


"""
*******************
    FAQ Category 
*******************
"""


class FAQ_Cateogry(models.Model):
    name = models.CharField(max_length=50)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self) -> str:
        return self.name


"""
*******************
    FAQ Model
*******************
"""


class FAQ(models.Model):
    faq_category_id = models.ForeignKey(FAQ_Cateogry, on_delete=models.CASCADE,
                                        related_name='FAQCateIds',
                                        related_query_name='FAQCateId',
                                        limit_choices_to={'is_active': True},)

    question = models.CharField(max_length=50)
    answer = models.CharField(max_length=50)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.faq_category_id} {self.question}"


"""
****************************************************************************************************************************************************
                                                         Contact Us 
****************************************************************************************************************************************************
"""


class ContactUs(models.Model):
    name = models.CharField(max_length=50)
    phone = models.CharField(max_length=20)
    email = models.EmailField(max_length=254)
    subject = models.CharField(max_length=50)
    description = models.TextField(max_length=500)

    is_solve = models.BooleanField(default=False)
    solve_timeshtamp = models.DateTimeField(
        auto_now=False, auto_now_add=False, blank=True, null=True)
    solve_by = models.CharField(max_length=50, blank=True, null=True)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.name} {self.email}"


"""
****************************************************************************************************************************************************
                                                         Ticket / Support 
****************************************************************************************************************************************************
"""


"""
*******************
    Issue Category 
*******************
"""


class Issue_Category(models.Model):

    Catename = models.CharField(max_length=50)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self) -> str:
        return self.Catename


"""
*******************
    Support Ticket
*******************
"""


class Support_Ticket(models.Model):

    ticket_no = models.CharField(
        max_length=50, unique=True, blank=True, null=True)

    client_User_Id = models.ForeignKey(User, on_delete=models.CASCADE,
                                       related_name='ClientUserIds',
                                       related_query_name='ClientUserId',
                                       limit_choices_to={'is_active': True}, blank=True, null=True)

    country_code = models.CharField(max_length=10, blank=True, null=True,)
    requester_phone = models.CharField(max_length=20, blank=True, null=True,)
    requester_email = models.EmailField(max_length=254, blank=True, null=True,)

    issue_Cate_id = models.ForeignKey(Issue_Category, on_delete=models.CASCADE,
                                      related_name='IssueCateIds',
                                      related_query_name='IssueCateId',
                                      limit_choices_to={'is_active': True}, blank=True, null=True)

    subject = models.CharField(max_length=50, blank=True, null=True,)
    description = models.TextField(max_length=500, blank=True, null=True,)

    order_id = models.CharField(max_length=20, blank=True, null=True,)

    is_closed = models.BooleanField(default=False)
    closing_details = models.TextField(max_length=500, blank=True, null=True, )
    closed_by = models.CharField(max_length=50, blank=True, null=True,)
    closing_timestamp = models.DateTimeField(blank=True, null=True,)

    status = models.CharField(max_length=50, choices=[("Open", "Open"), ("In_Progress", "In_Progress"), ("Closed", "Closed"), ("Reopen", "Reopen"), ],
                              default="Open")

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    # def __str__(self) -> str:
    #     return f"{self.issue_Cate_id} {self.ticket_no}"


"""
****************************************************************************************************************************************************
                                                            Notification
****************************************************************************************************************************************************
"""


class Notification(models.Model):

    usersType = models.CharField(max_length=50, choices=[("All", "All"), ("Admin", "Admin"), ("Agent", "Agent"), ("EndUser", "EndUser"), ],
                                 default="All")
    title = models.CharField(max_length=100, blank=True, null=True,)
    body = models.TextField(max_length=251, blank=True, null=True,)

    Notif_image = models.ImageField(
        upload_to="Notification", blank=True, null=True, )

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)


"""
****************************************************************************************************************************************************
                                                            Banner 
****************************************************************************************************************************************************
"""


class Banner(models.Model):

    banner_title = models.CharField(max_length=100, blank=True, null=True,)
    banner_caption = models.TextField(
        max_length=500, blank=True, null=True,)
    banner_image = models.ImageField(
        upload_to="Banner", blank=True, null=True, )
    banner_start = models.DateTimeField(
        auto_now=False, auto_now_add=False, null=True, blank=True)
    banner_end = models.DateTimeField(
        auto_now=False, auto_now_add=False, null=True, blank=True)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)


"""
****************************************************************************************************************************************************
                                                            Offer 
****************************************************************************************************************************************************
"""


class Offer_discount(models.Model):

    offer_name = models.CharField(max_length=100, blank=True, null=True,)
    offer_description = models.TextField(
        max_length=500, blank=True, null=True,)

    offer_code = models.CharField(
        max_length=100, blank=True, null=True, unique=True)

    offer_amount = models.IntegerField(null=True, blank=True)

    offer_percentage = models.DecimalField(
        max_digits=4, decimal_places=2, null=True, blank=True)
    offer_upto_value = models.IntegerField(null=True, blank=True)

    offer_minium_value = models.IntegerField(null=True, blank=True)

    offer_start = models.DateTimeField(
        auto_now=False, auto_now_add=False, null=True, blank=True)
    offer_end = models.DateTimeField(
        auto_now=False, auto_now_add=False, null=True, blank=True)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):

        return f"{self.offer_name}"
