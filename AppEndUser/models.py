"""
*************************************
        Imported Packages
*************************************
"""

# By Default
from email.policy import default
from django.db import models

# Translations
from django.utils.translation import gettext_lazy as _

# User Model from AppAdmin Application
from AppAdmin.models import (
    User,
    CourierCompany,
)

"""
**************************************************************************
                            Create Your models here
**************************************************************************
"""


"""
*************************************
         Sender & Receiver Address
*************************************
"""


class Sender_Receiver_Address(models.Model):

    # Relationship with Admin Application - User Model
    user_idSRAdd = models.ForeignKey(User, on_delete=models.CASCADE,
                                     related_name='EUAddUserIDs',
                                     related_query_name='EUAddUserID',
                                     limit_choices_to={
                                         'is_active': True, "user_type": "EndUser"},
                                     null=True, blank=True)

    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    country_code = models.CharField(max_length=50)
    phone = models.CharField(max_length=20)
    address = models.TextField(max_length=500)
    landmarks = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    pincode = models.CharField(max_length=50)
    country = models.CharField(max_length=50)

    latitude = models.CharField(max_length=50)
    longitude = models.CharField(max_length=50)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        name = (f" {self.first_name} {self.last_name}")
        return (name)


"""
*************************************
            Card        
*************************************
"""


class User_Card_Details(models.Model):

    UserCard_id = models.ForeignKey(User, on_delete=models.CASCADE,
                                    related_name='CardEndUserIDs',
                                    related_query_name='CardEndUserID',
                                    limit_choices_to={
                                        'is_active': True, "user_type": "EndUser"},
                                    null=True, blank=True)

    Owner_name = models.CharField(max_length=112, null=True, blank=True)
    card_number = models.CharField(max_length=112, null=True, blank=True)
    exp_date = models.CharField(max_length=10, null=True, blank=True)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        name = (f" {self.UserCard_id} {self.Owner_name}")
        return (name)


"""
**************************************************************************
                            Order 
**************************************************************************
"""


class End_User_Order(models.Model):

    order_date = models.DateField(auto_now=False, auto_now_add=True,
                                  null=True, blank=True)

    booking_order_id = models.CharField(max_length=50, unique=True,
                                        null=True, blank=True)

    company_name_id = models.ForeignKey(CourierCompany, on_delete=models.CASCADE,
                                        related_name='EUCourierCompanyIDs',
                                        related_query_name='EUCourierCompanyID',
                                        limit_choices_to={
                                            'is_active': True}, null=True, blank=True)

    awb_no = models.CharField(max_length=50, unique=True,
                              null=True, blank=True)

    user_idEndOrder = models.ForeignKey(User, on_delete=models.CASCADE,
                                        related_name='EUorderUserIDs',
                                        related_query_name='EUorderUserID',
                                        limit_choices_to={
                                            'is_active': True, "user_type": "EndUser"},
                                        null=True, blank=True)

    Sender_id = models.ForeignKey(Sender_Receiver_Address, on_delete=models.CASCADE,
                                  related_name='EUSenderIDs',
                                  related_query_name='EUSenderID',
                                  limit_choices_to={
                                      'is_active': True}, null=True, blank=True)

    Receiver_id = models.ForeignKey(Sender_Receiver_Address, on_delete=models.CASCADE,
                                    related_name='EURecevierIDs',
                                    related_query_name='EURecevierID',
                                    limit_choices_to={
                                        'is_active': True}, null=True, blank=True)

    origin = models.CharField(max_length=100, null=True, blank=True)
    destination = models.CharField(max_length=100, null=True, blank=True)

    ServiceType = models.CharField(max_length=50, choices=[("Standard", "Standard"),
                                                           ("Priority", "Priority"), ], default="Standard")

    ShipmentType = models.CharField(max_length=50, choices=[("Documents", "Documents"),
                                                            ("Parcel", "Parcel"), ], default="Documents")

    TravelBy = models.CharField(max_length=50, choices=[("Air", "Air"), ("Surface", "Surface"),
                                                        ("Air/Surface", "Air/Surface"), ], default="Air/Surface")

    content_of_shipment = models.CharField(max_length=200, null=True,
                                           blank=True)

    value_of_goods = models.IntegerField(null=True, blank=True)

    weight = models.IntegerField(null=True, blank=True)

    dimension = models.CharField(max_length=100, null=True, blank=True)

    volumetric_weight = models.IntegerField(null=True, blank=True)

    texable_value = models.DecimalField(max_digits=10, decimal_places=2,
                                        null=True, blank=True)

    sgst = models.DecimalField(max_digits=10, decimal_places=2,
                               null=True, blank=True)

    cgst = models.DecimalField(max_digits=10, decimal_places=2,
                               null=True, blank=True)

    pickup_charge = models.IntegerField(null=True, blank=True)

    totalcharge = models.DecimalField(max_digits=10, decimal_places=2,
                                      null=True, blank=True)

    booking_tnc = models.BooleanField(default=True)

    eway_bill_no = models.CharField(max_length=200, null=True,
                                    blank=True)

    eway_bill_date = models.DateField(auto_now=False, auto_now_add=False, null=True,
                                      blank=True)

    endUser_gstNo = models.CharField(max_length=200, null=True,
                                     blank=True)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        return self.booking_order_id
