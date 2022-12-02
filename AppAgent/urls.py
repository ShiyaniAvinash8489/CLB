"""
*************************************
        Imported Packages 
*************************************
"""


# By Default
from django.contrib import admin
from django.urls import path, include


# Agent APP- Views
from AppAgent.views import (

    # Verify Email & Phone
    Agent_Send_EmailPhone_OTP_views,
    Agent_Verify_Mobile_OTP_Views,
    Agent_Verify_Email_OTP_Views,

    # Register Agent
    Register_Agent_User_View,
    Create_Agent_Address_Views,
    Create_Agent_Bank_Details_Views,
    Create_Agent_KYC_Details_Views,

    # Agent Login
    AgentLogin_Views,

    # Update Profile
    Agent_Change_Password_view,
    Agent_Update_Profile_View,

)


"""
**************************************************************************
                            ULRS
**************************************************************************
"""

urlpatterns = [
    # Register - Verify Email & Phone
    path("Send-Email-Phone-OTP/",
         Agent_Send_EmailPhone_OTP_views.as_view(), name="SendEmailPhoneOTP"),
    path("Agent-Verify-Mobile-OTP/",
         Agent_Verify_Mobile_OTP_Views.as_view(), name="AgentVerifyMobielOTP"),
    path("Agent-Verify-Email-OTP/",
         Agent_Verify_Email_OTP_Views.as_view(), name="AgentVerifyEmailOTOP"),

    # Register Agent
    path("Register-Agent/", Register_Agent_User_View.as_view(),
         name="RegisterAgentUser"),
    path("Agent-Address/", Create_Agent_Address_Views.as_view(),
         name="CreateAgentAddress"),
    path("Agent-Bank-Details", Create_Agent_Bank_Details_Views.as_view(),
         name="AgentBankDetails"),
    path("Agent-KYC-Details/", Create_Agent_KYC_Details_Views.as_view(),
         name="CreateAgentKYCDetails"),

    # Agent Login
    path("Agent-Login/", AgentLogin_Views.as_view(), name="AgentLogin"),

    # Agent Change Password
    path("Agent-Change-Password/<int:pk>/", Agent_Change_Password_view.as_view(),
         name="AgentChangePassword"),
    path("Agent-Update-Profile/<int:pk>/",
         Agent_Update_Profile_View.as_view(), name="AgentUpdateProfile"),


]
