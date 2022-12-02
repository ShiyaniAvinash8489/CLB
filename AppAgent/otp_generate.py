"""
*************************************
        Imported Packages
*************************************
"""


# For genrating OTP
import random
import math

# Date Time
import datetime
from datetime import timedelta

# Send Email
from AppAdmin.EmailConfig import SendEmail

# Django Modules
from django.template.loader import get_template
from django.db.models import Q


# Error Log
from AppAdmin.Error_Log import Error_Log


# # Model Admin
# from AppAdmin.models import User

# Model Agent
from AppAgent.models import (Agent_Verify_Email_Mobile)
"""
******************************************************************************************************************
                                    Email  Store 
******************************************************************************************************************
"""


"""
*************************************
        OTP Generate - Numric
*************************************
"""


def generateOTP():

    string = '0123456789'
    OTP = ""
    length = len(string)
    for i in range(6):
        OTP += string[math.floor(random.random() * length)]

    return OTP


"""
*************************************
        OTP Generate - Alpha Numric
*************************************
"""

# function to generate OTP


def generateOTPAlphaNumberic():

    # Declare a string variable
    # which stores all string
    string = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    OTP = ""
    length = len(string)
    for i in range(6):
        OTP += string[math.floor(random.random() * length)]

    return OTP


"""
******************************************************************************************************************
                                    Send OTP to email
******************************************************************************************************************
"""


def SendEmailForOTP(email, id):
    try:
        Gen_OTP = generateOTP()

        Agent_Verify_Email_Mobile.objects.filter(
            Q(email=email) & Q(is_verify=False) & Q(exp_datetime__gt=datetime.datetime.now())).delete()

        Exp_Time = datetime.datetime.now() + timedelta(minutes=5)

        Agent_Verify_Email_Mobile.objects.filter(id=id).update(
            otp=str(Gen_OTP), exp_datetime=Exp_Time)

        SendEmail.send_email({
            "email_body": get_template('OTP_HTML_Template.html').render({
                "first_name": "Hello User,",
                'verfiy_OTP': Gen_OTP}),
            "to_email": email,
            "email_subject": "Verify Email OTP ", })

    except Exception as e:
        Error_Log(e)

    return True
