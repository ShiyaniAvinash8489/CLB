"""
*************************************
        Imported Packages
*************************************
"""

# By Default
from operator import truediv
from django.db import models

# Translations
from django.utils.translation import gettext_lazy as _

# User Model from AppAdmin Application
from AppAdmin.models import (
    User,
)

"""
**************************************************************************
                            Create Your models here
**************************************************************************
"""


"""
*************************************
         Agent Address
*************************************
"""


class Agent_Address(models.Model):

    # Relationship with Admin Application - User Model
    user_idAddress = models.ForeignKey(User, on_delete=models.CASCADE,
                                       related_name='AgentAddUserIDs',
                                       related_query_name='AgentAddUserID',
                                       limit_choices_to={
                                           'is_active': True, "user_type": "Agent"},
                                       null=True, blank=True)

    address_line_1 = models.TextField(max_length=150)
    address_line_2 = models.TextField(max_length=150, null=True, blank=True)

    landmarks = models.CharField(max_length=50)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    pincode = models.CharField(max_length=50)
    country = models.CharField(max_length=50)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)

    def __str__(self):
        name = (f"{self.id}")
        return (name)


"""
*************************************
         Agent Bank Details 
*************************************
"""


class Agent_Bank_Details(models.Model):

    user_idBank = models.ForeignKey(User, on_delete=models.CASCADE,
                                    related_query_name='AgentBankUserID',
                                    limit_choices_to={
                                        'is_active': True, "user_type": "Agent"},
                                    )

    bank_name = models.CharField(max_length=50,)
    branch_name = models.CharField(max_length=50)
    IFSC_code = models.CharField(max_length=20)
    account_number = models.CharField(max_length=50)
    cancel_cheque = models.ImageField(upload_to='Cancel_cheque',)

    is_verify = models.BooleanField(default=False)
    is_verify_by = models.CharField(max_length=50, null=True, blank=True)

    is_active = models.BooleanField(default=True)

    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)


"""
*************************************
         Agent KYC
*************************************
"""


class Agent_KYC(models.Model):

    user_idKYC = models.ForeignKey(User, on_delete=models.CASCADE,
                                   related_name='AgentKYCUserIDs',
                                   related_query_name='AgentKYCUserID',
                                   limit_choices_to={
                                       'is_active': True, "user_type": "Agent"},
                                   null=True, blank=True)

    UserKYCImage = models.ImageField(upload_to='KYC',)

    KYC_Name = models.CharField(max_length=50)

    frontside_image = models.ImageField(upload_to='KYC',)
    backside_image = models.ImageField(upload_to='KYC', null=True, blank=True)

    is_verify = models.BooleanField(default=False)
    is_verify_by = models.CharField(max_length=50, null=True, blank=True)

    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True)
    created_by = models.CharField(max_length=50, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True)
    updated_by = models.CharField(max_length=50, null=True, blank=True)


"""
*************************************
        Verify Email & Mobile 
*************************************
"""


class Agent_Verify_Email_Mobile(models.Model):

    email = models.EmailField(max_length=254)
    is_verify_email = models.BooleanField(default=False)

    otp = models.CharField(max_length=7, null=True, blank=True)
    gen_datetime = models.DateTimeField(auto_now_add=True)
    exp_datetime = models.DateTimeField(null=True, blank=True)

    is_verify = models.BooleanField(default=False)

    country_code = models.CharField(max_length=50)
    phone = models.CharField(max_length=20)
    is_verify_phone = models.BooleanField(default=False)

    def __str__(self):
        return self.email + " " + self.phone
