"""
*************************************
    Packages
*************************************
"""
# Decouple
from decouple import config

# Date Time
import datetime

# Random
import random

# Admin Models
from AppAdmin.models import (
    Support_Ticket,
    User,
    SystemAndDeviceLog,
)


# FCM
import firebase_admin
from firebase_admin import credentials, messaging


"""
****************************************************************************************************************************************************
                                                    Generate Auto Ticket Number
****************************************************************************************************************************************************
"""


def CheckTicketNumber():

    date = datetime.datetime.now()
    tktNumber = f"tkt{date.strftime('%Y')}{date.strftime('%m')}{date.strftime('%d')}{random.randint(1,1000)}"

    return tktNumber


"""
****************************************************************************************************************************************************
                                                    Generate Auto Order Number
****************************************************************************************************************************************************
"""


def Check_And_Generate_Order_Number():

    date = datetime.datetime.now()
    OrderNumber = f"{random.randint(1,999999)}{date.strftime('%Y')}{date.strftime('%m')}{date.strftime('%d')}"

    return OrderNumber


"""
****************************************************************************************************************************************************
                                                            FCM 
****************************************************************************************************************************************************
"""

# Store
cred = credentials.Certificate(config("GOOGLE_FCM"))

# Initialize App
firebase_admin.initialize_app(cred)

# Failed Tokens
failed_tokens = []


# Function for Sending Push Notification
def sendPush(usersType, title, msg, dataObject=None):

    if usersType == "All":

        registration_token = [ActiveFCMToken["fcm_token"]
                              for ActiveFCMToken in SystemAndDeviceLog.objects.filter(
            active_fcm=True).values("fcm_token")]

    elif usersType == "Admin":

        registration_token = [ActiveFCMToken["fcm_token"]
                              for ActiveFCMToken in SystemAndDeviceLog.objects.filter(
            active_fcm=True, user_idSysLog__user_type="Admin").values("fcm_token")]

    elif usersType == "Agent":

        registration_token = [ActiveFCMToken["fcm_token"]
                              for ActiveFCMToken in SystemAndDeviceLog.objects.filter(
            active_fcm=True, user_idSysLog__user_type="Agent").values("fcm_token")]

    elif usersType == "EndUser":

        registration_token = [ActiveFCMToken["fcm_token"]
                              for ActiveFCMToken in SystemAndDeviceLog.objects.filter(
            active_fcm=True, user_idSysLog__user_type="EndUser").values("fcm_token")]

    # See documentation on defining a message payload.
    message = messaging.MulticastMessage(
        notification=messaging.Notification(
            title=title,
            body=msg
        ),
        data=dataObject,
        tokens=registration_token,
    )

    # Send a message to the device corresponding to the provided
    # registration token.
    response = messaging.send_multicast(message)

    # Response is a message ID string.
    print('Successfully sent message:', response.success_count)

    if response.failure_count > 0:
        responses = response.responses

        for idx, resp in enumerate(responses):
            if not resp.success:

                # The order of responses corresponds to the order of the registration tokens.
                failed_tokens.append(registration_token[idx])

                # FCM Token Deactive
                SystemAndDeviceLog.objects.filter(
                    fcm_token=registration_token[idx]).update(active_fcm=False)

        print('List of tokens that caused failures: {0}'.format(failed_tokens))

    return {"Success_Count": "response.success_count", "Failed_token": "failed_tokens"}
