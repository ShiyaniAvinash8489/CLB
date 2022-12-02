"""
*************************************
        Imported Packages 
*************************************
"""


# By Default
from django.contrib import admin
from django.urls import path, include


# Admin APP- Views
from AppAdmin.views import (
    # Create Admin User
    RegisterAdminuser_View,

    # Update Admin User Profile
    UpdateAdminUserProfile_View,

    # Change Password
    ChangeAdminPassword_view,

    # Verify Email
    VerifyEmail_Views,

    # Super Admin Login
    SuperAdminLogin_Views,
    AdminLogin_Views,
    AdminVerifyLoginOTP_Views,

    # Forget Password
    RequestPasswordResetEmail_Views,
    PasswordTokenCheckAPI_Views,
    SetNewPasswordAPI_View,



    # System and Device Log - Create
    SystemAndDeviceLog_Create_Views,

    # Encrypt & Decrypt
    Encrypt_Views,
    Decrypt_Views,

    # Upload Pincode CSV File
    ImportCSVFileViews_Pincode,
    ImportCSVFileViews_Price,
    ImportCSVFileViews_PriceForUs,

    # Booking Slot
    Get_All_Booking_Slot_View,
    Create_Booking_Slot_View,
    Update_Booking_Slot_View,
    Hard_Delete_Booking_Slot_View,

    # Pincode
    Get_All_Pincode_Views,
    Get_All__Delete_Pincode_Views,
    Create_Pincode_View,
    Update_Pincode_View,
    Hard_Delete_Pincode_View,
    Active_Deleted_Pincode_Views,
    Active_CLBPickup_Pincode_Views,
    dective_CLBPickup_Pincode_Views,


    # Get User Details
    Admin_User_Details_Views,
    Get_Verify_agent_Details,
    Get_unVerify_agent_Details,

    # Get Agent Details
    Agent_All_Verified_KYC_List_views,
    Agent_All_UNverified_KYC_List_views,
    Agent_All_UNverified_bank_List_views,
    Agent_All_Verified_Bank_List_views,

    # Soft Delete user
    softDelete_AdminUser_Views,
    softDelete_Agent_User_Views,

    # Agent Verification
    Agent_Verify_KYC_byAdmin_View,
    Agent_Verify_Bank_byAdmin_View,

    # Courier Company
    Register_Courier_Company_View,
    Update_Courier_Profile_View,
    Get_All_Coruier_views,
    Get_Singal_Coruier_views,
    Delete_Soft_Courier_views,


    # Review CLB & COurier Company
    CLB_Review_by_Rating,
    Hard_Delete_CLB_Review_View,
    List_CLB_Review_by_Rating_View,
    CourierCompany_Review_by_Company,
    Hard_Delete_Courier_Company_Review_View,
    ListReviewByCompany_Review,

    # Price
    Create_Price_for_Customer_View,
    Update_Price_for_Customer_View,
    Delete_Soft_Price_For_Customer_views,
    Get_Price_List_of_Customer_views,
    Create_Price_for_Us_View,
    Update_Price_for_US_View,
    Delete_Soft_Price_For_us_views,
    Get_Price_List_of_US_views,

    #FAQ - Cateogry
    Create_FAQ_Category_views,
    Update_FAQ_Category_views,
    DeleteSoft_FAQ_Category_views,
    Get_FAQ_Category_views,
    List_FAQ_Category_Views,

    # FAQ
    Create_FAQ_views,
    Update_FAQ_views,
    DeleteSoft_FAQ_views,
    List_FAQ_Views,
    Get_FAQ_views,

    # FAQ with searching Category
    Get_FAQ_Category_With_QA_views,


    # Contact Us
    Create_ContactUs_views,
    Update_ContactUs_views,
    DeleteSoft_ContactUs_views,
    List_ContactUs_Views,
    Get_ContactUs_views,


    # Issue Category
    Create_Issue_Category_views,
    Update_Issue_Category_views,
    DeleteSoft_Issue_Category_views,
    Get_Issue_Category_views,
    List_Issue_Category_Views,

    # Support Ticket
    Get_SupportTicket_AdminViews,
    List_Open_Support_Ticket_AdminViews,
    List_In_Progress_Support_Ticket_AdminViews,
    List_Closed_Support_Ticket_AdminViews,
    Update_Support_Ticket_views,

    # Notificaiton
    Create_Notification_views,
    List_Notification_AdminViews,
    Get_Notification_AdminViews,
    DeleteSoft_Notification_views,


    # Banner
    Create_Banner_Views,
    Update_Banner_Views,
    DeleteSoft_Banner_views,
    Get_Banner_AdminViews,
    List_deleted_Banner_AdminViews,
    List_Active_Banner_AdminViews,
    List_Expired_Banner_AdminViews,
    List_Future_Banner_AdminViews,

    # offer
    Create_Offer_Views,
    Update_Offer_Views,
    DeleteSoft_Offer_views,
    Get_Offer_AdminViews,
    List_deleted_Offer_AdminViews,
    List_Active_Offer_AdminViews,
    List_Expired_Offer_AdminViews,
    List_Future_Offer_AdminViews,

    # Search
    Search_AdminUser_views,
    Search_pincode_views,
    Search_AgentUser_views,
    Search_EndUser_views,
    Search_Courier_Company_views,
    Search_FAQ_views,
    Search_Contact_Us_views,
    Search_Support_Ticket_views,
    Search_Notification_views,
    Search_Banner_views,
    Search_Offer_views,



)


"""
**************************************************************************
                            ULRS
**************************************************************************
"""

urlpatterns = [
    # ************************* Admin User *************************

    # Create Admin user
    path("RegisterAdminUser/", RegisterAdminuser_View.as_view(), name="RegisterUser"),

    # Update Profile
    path("UpdateAdminUserProfile/<int:pk>/", UpdateAdminUserProfile_View.as_view(),
         name="UpdateAdminUserProfile"),

    # Change Password
    path("ChangeAdminPassword/<int:pk>/", ChangeAdminPassword_view.as_view(),
         name="ChangeAdminPassword"),


    # Verify Email
    path("Email-Verify/", VerifyEmail_Views.as_view(), name="Email-Verify"),

    # Super Admin Login
    path("SuperAdminLogin/", SuperAdminLogin_Views.as_view(),
         name="Super-Admin-Login"),
    path("AdminLogin/", AdminLogin_Views.as_view(),
         name="Super-Admin-Login"),
    path("AdminVerifyLoginOTP/", AdminVerifyLoginOTP_Views.as_view(),
         name="Admin-Verify-Login-OTP"),


    # Forget Password

    path('Request-Reset-Email/', RequestPasswordResetEmail_Views.as_view(),
         name="RequestResetEmail"),
    path('Password-Reset/<uidb64>/<token>/',
         PasswordTokenCheckAPI_Views.as_view(), name='passwordResetConfirm'),
    path('Password-Reset-Complete/', SetNewPasswordAPI_View.as_view(),
         name='PasswordResetComplete'),



    # ************************* Others *************************
    # System and Device Log - Create
    path("SystemAndDeviceLog/", SystemAndDeviceLog_Create_Views.as_view(),
         name="CreateSystemDeviceLog"),

    # Encrytp & Decrypt - get
    path("Encrytp/", Encrypt_Views.as_view(), name="EncrytpData"),
    path("Decrypt/", Decrypt_Views.as_view(), name="DecryptData"),

    # Upload Pincode CSV
    path("Upload-Pincode-CSV/", ImportCSVFileViews_Pincode.as_view(),
         name="UploadPincodeCSV"),
    path("Upload-PriceForCustomer-CSV/", ImportCSVFileViews_Price.as_view(),
         name="UploadPriceForCustomerCSV"),
    path("Upload-PriceForCLB-CSV/", ImportCSVFileViews_PriceForUs.as_view(),
         name="UploadPriceForCLBCSV"),

    # Booking Slot
    path("Get-All-Booking-Slot/", Get_All_Booking_Slot_View.as_view(),
         name="GetAllBookingSlot"),
    path("Add-Booking-Slot/", Create_Booking_Slot_View.as_view(),
         name="CreateBookingSlot"),
    path("Update-Booking-Slot/<int:pk>/", Update_Booking_Slot_View.as_view(),
         name="UpdateeBookingSlot"),
    path("Hard-Delete-Booking-Slot/<int:pk>/",
         Hard_Delete_Booking_Slot_View.as_view(), name="HardDeleteBookingSlot"),


    # ************************* Pincode *************************
    path("Get-All-Picode/", Get_All_Pincode_Views.as_view(), name="Get_All_Pincode"),
    path("Get-All-Delete-Picode/", Get_All__Delete_Pincode_Views.as_view(),
         name="Get_All_DeletedPincode"),
    path("Create-Pincode/", Create_Pincode_View.as_view(), name="CreatePincode"),
    path("Update-Pincode/<int:pk>/", Update_Pincode_View.as_view(),
         name="UpdatePincode"),
    path("Hard-Delete-Pincode/<int:pk>/",
         Hard_Delete_Pincode_View.as_view(), name="HardDeletePincode"),
    path("Activate_Pincode/<int:pk>/",
         Active_Deleted_Pincode_Views.as_view(), name="ActiveDeltedPIncode"),
    path("Activate_CLB_Pickup/<int:pincode>/",
         Active_CLBPickup_Pincode_Views.as_view(), name="ActivateCLBPickup"),
    path("deactivate_CLB_Pickup/<int:pincode>/",
         dective_CLBPickup_Pincode_Views.as_view(), name="deactivateCLBPickup"),

    # ************************* Soft Delete User  *************************


    path("SoftDetete_AdminUser/<int:pk>/",
         softDelete_AdminUser_Views.as_view(), name="SoftDeleteADminUser"),
    path("SoftDetete_Agent_User/<int:pk>/",
         softDelete_Agent_User_Views.as_view(), name="SoftDeleteAgentUser"),

    # ************************* Get User Details  *************************

    path("Get-Admin-user/", Admin_User_Details_Views.as_view(),
         name="GetAdminUserDetails"),
    path("Get-Verify-Agent-user/", Get_Verify_agent_Details.as_view(),
         name="GetVerifyAgentUserDetails"),
    path("Get-UNVerify-Agent-user/", Get_unVerify_agent_Details.as_view(),
         name="GetUNVerifyAgentUserDetails"),

    # ************************* Agent *************************


    path("Get-Verified_KYC/<int:pk>/", Agent_All_Verified_KYC_List_views.as_view(),
         name="GetVerifiedKYCByUser"),
    path("Get-Unverified_KYC/<int:pk>/", Agent_All_UNverified_KYC_List_views.as_view(),
         name="GetUnverifiedKYCByUser"),

    path("Get-Verified_Bank/<int:pk>/", Agent_All_Verified_Bank_List_views.as_view(),
         name="GetVerifiedBankByUser"),
    path("Get-Unverified_Bank/<int:pk>/", Agent_All_UNverified_bank_List_views.as_view(),
         name="GetUnverifiedBankByUser"),

    # ************************* Agent *************************

    path("Agent-KYC-Verification/<int:pk>/",
         Agent_Verify_KYC_byAdmin_View.as_view(), name="AgentKYCVerification"),
    path("Agent-Bank-Verification/<int:pk>/",
         Agent_Verify_Bank_byAdmin_View.as_view(), name="AgentBankVerification"),


    # *************************  Courier Company  *************************

    path("Register-Courier-Company/",
         Register_Courier_Company_View.as_view(), name="RegisterCourierCompany"),
    path("Update-Courier-Company/<int:pk>/",
         Update_Courier_Profile_View.as_view(), name="UpdateCourierCompany"),
    path("Get-Singal-courier-company-details/<int:pk>/",
         Get_Singal_Coruier_views.as_view(), name="getSingalCourierData"),
    path("Get-All-Coruier-Company-List/", Get_All_Coruier_views.as_view(),
         name="getAllCourierCompanyList"),
    path("Soft-Delete-Courier-Company/<int:pk>/",
         Delete_Soft_Courier_views.as_view(), name='softdeleteCouriercompany'),

    # *************************  Review  CLB & Courier Company  *************************

    path("Get_Review_CLB_Avg/",
         CLB_Review_by_Rating.as_view(), name="GetAllReviewCLBAvg"),
    path("HardDelete_CLB_Review/<int:pk>/", Hard_Delete_CLB_Review_View.as_view(),
         name="HardDeleteCLBReview"),
    path("Get_CLB_Review_By_Rating/<int:rating>/", List_CLB_Review_by_Rating_View.as_view(),
         name="getCLBReviewbyRating"),
    path("Get_Review_by_Courier_Company_Review/",
         CourierCompany_Review_by_Company.as_view(), name="GetAllReviewByCompnay"),
    path("HardDelete_Courier_Company_Review/<int:pk>/", Hard_Delete_Courier_Company_Review_View.as_view(),
         name="HardDeleteCourierCompanyReview"),
    path("Get-All-Review-Company/<int:Cou_Com_id>/",
         ListReviewByCompany_Review.as_view(), name="GetALReviewByCompanySearch"),


    # *************************  Price  *************************
    path("Create-Price-For-Customer/", Create_Price_for_Customer_View.as_view(),
         name="CreatePriceForCustomer"),
    path("update-Price-For-Customer/<int:pk>/", Update_Price_for_Customer_View.as_view(),
         name="updatePriceForCustomer"),
    path("SoftDelete-Price-For-Customer/<int:pk>", Delete_Soft_Price_For_Customer_views.as_view(),
         name="SoftDeletePriceForCustomer"),
    path("Get-Price-For-Customer/<int:pk>/", Get_Price_List_of_Customer_views.as_view(),
         name="GetPriceForCustomer"),
    path("Create-Price-For-CLB/", Create_Price_for_Us_View.as_view(),
         name="CreatePriceForCLB"),
    path("update-Price-For-CLB/", Update_Price_for_US_View.as_view(),
         name="updatePriceForCLB"),
    path("SoftDelete-Price-For-CLB/", Delete_Soft_Price_For_us_views.as_view(),
         name="SoftDeletePriceForCLB"),
    path("Get-Price-For-CLB/<int:pk>/", Get_Price_List_of_US_views.as_view(),
         name="GetPriceForCLB"),


    # *************************  FAQ Category  *************************
    path("Create-FAQ-Category/", Create_FAQ_Category_views.as_view(),
         name="CreateFAQCategory"),
    path("update-FAQ-Category/<int:pk>/", Update_FAQ_Category_views.as_view(),
         name="updateFAQCategory"),
    path("SoftDelete-FAQ-Category/<int:pk>", DeleteSoft_FAQ_Category_views.as_view(),
         name="SoftDeleteFAQCategory"),
    path("Get-FAQ-Category/<int:pk>/",
         Get_FAQ_Category_views.as_view(), name="GetFAQCategory"),
    path("List-FAQ-Category/", List_FAQ_Category_Views.as_view(),
         name="ListAllFAQCategory"),


    # *************************  FAQ   *************************
    path("Create-FAQ/", Create_FAQ_views.as_view(),
         name="CreateFAQ"),
    path("update-FAQ/<int:pk>/", Update_FAQ_views.as_view(),
         name="updateFAQ"),
    path("SoftDelete-FAQ/<int:pk>", DeleteSoft_FAQ_views.as_view(),
         name="SoftDeleteFAQ"),
    path("Get-FAQ/<int:pk>/",
         Get_FAQ_views.as_view(), name="GetFAQ"),
    path("List-FAQ/", List_FAQ_Views.as_view(),
         name="ListAllFAQ"),

    # *************************  FAQ   *************************
    path("List-FAQ-Category-With-QA/<int:pk>/", Get_FAQ_Category_With_QA_views.as_view(),
         name="ListAllFAQCategory"),



    # *************************  Contact Us   *************************
    path("Create-ContactUs/", Create_ContactUs_views.as_view(),
         name="CreateContactUs,"),
    path("update-Contactus/<int:pk>/", Update_ContactUs_views.as_view(),
         name="UpdateContactUs"),
    path("SoftDelete-ContactUs/<int:pk>", DeleteSoft_ContactUs_views.as_view(),
         name="SoftDeleteContactUs"),
    path("Get-ContactUs/<int:pk>/",
         Get_ContactUs_views.as_view(), name="GetContactUs"),
    path("List-ContactUs/", List_ContactUs_Views.as_view(),
         name="ListAllContactUs"),


    # *************************  Issue Category  *************************
    path("Create-Issue-Category/", Create_Issue_Category_views.as_view(),
         name="CreateIssueCategory"),
    path("update-Issue-Category/<int:pk>/",
         Update_Issue_Category_views.as_view(), name="updateIssueCategory"),
    path("SoftDelete-Issue-Category/<int:pk>",
         DeleteSoft_Issue_Category_views.as_view(), name="SoftDeleteIssueCategory"),
    path("Get-Issue-Category/<int:pk>/",
         Get_Issue_Category_views.as_view(), name="GetIssueCategory"),
    path("List-Issue-Category/", List_Issue_Category_Views.as_view(),
         name="ListAllIssueCategory"),


    # *************************  Support Ticket- admin  *************************
    path("Get-Support-Ticket-admin/<int:pk>/",
         Get_SupportTicket_AdminViews.as_view(), name="getsupportticketadmin"),
    path("List-Open-Ticket-admin/", List_Open_Support_Ticket_AdminViews.as_view(),
         name="ListOpenTicketadmin"),
    path("List-In_Progress-Ticket-admin/", List_In_Progress_Support_Ticket_AdminViews.as_view(),
         name="ListIn_ProgressTicketadmin"),
    path("List-Closed-Ticket-admin/", List_Closed_Support_Ticket_AdminViews.as_view(),
         name="ListIn_ProgressTicketadmin"),
    path("update-admin-Support-Ticket/<int:pk>/",
         Update_Support_Ticket_views.as_view(), name="SupportTikcetUpdateadmin"),


    # *************************  Notification  *************************
    path("Create-Notification/", Create_Notification_views.as_view(),
         name="CreateNotificationAdmin"),
    path("List-All-Notification/", List_Notification_AdminViews.as_view(),
         name="listallnotificationviews"),
    path("Get-Notification/<int:pk>/",
         Get_Notification_AdminViews.as_view(), name="GetOneNotificaiton"),
    path("Delete-soft-Notification/<int:pk>/",
         DeleteSoft_Notification_views.as_view(), name="SoftDeleteNotificaiton"),


    # *************************  Banner  *************************
    path("Create-Banner/", Create_Banner_Views.as_view(), name="CreateBannerViews"),
    path("Update-Banner/<int:pk>", Update_Banner_Views.as_view(),
         name="UpdateBannerViews"),
    path("Soft-Delete-Banner/<int:pk>/",
         DeleteSoft_Banner_views.as_view(), name="softdeletebanner"),
    path("Single-banner-data/<int:pk>/",
         Get_Banner_AdminViews.as_view(), name="GetSingleBanner"),
    path("deleted-Banner-list/", List_deleted_Banner_AdminViews.as_view(),
         name="deletedbannerlist"),
    path("Active-Banner-list/", List_Active_Banner_AdminViews.as_view(),
         name="activeBannerList"),
    path("Expired-Banner-list/", List_Expired_Banner_AdminViews.as_view(),
         name="ExpiredBannerList"),
    path("Future-Banner-list/", List_Future_Banner_AdminViews.as_view(),
         name="FutureBannerList"),



    # *************************  Offer  *************************
    path("Create-Offer/", Create_Offer_Views.as_view(), name="CreateOfferViews"),
    path("Update-offer/<int:pk>", Update_Offer_Views.as_view(),
         name="UpdateOfferViews"),
    path("Soft-Delete-offer/<int:pk>/",
         DeleteSoft_Offer_views.as_view(), name="softdeleteoffer"),
    path("Single-Offer-data/<int:pk>/",
         Get_Offer_AdminViews.as_view(), name="GetSingleOffer"),
    path("deleted-Offer-list/", List_deleted_Offer_AdminViews.as_view(),
         name="deletedOfferlist"),
    path("Active-Offer-list/", List_Active_Offer_AdminViews.as_view(),
         name="activeOfferList"),
    path("Expired-Offer-list/", List_Expired_Offer_AdminViews.as_view(),
         name="ExpiredOfferList"),
    path("Future-Offer-list/", List_Future_Offer_AdminViews.as_view(),
         name="FutureOfferList"),


    # *************************  Search   *************************
    # Search User
    path("Search_Admin_User/", Search_AdminUser_views.as_view(),
         name=" Search_Admin_User"),

    # pincode
    path("Search-Pincode-Admin/", Search_pincode_views.as_view(),
         name="SearchPincodebyAdmin"),

    # Agent User
    path("Search-Agent-User/", Search_AgentUser_views.as_view(),
         name="SearchAgentbyAdmin"),

    # EndUser User
    path("Search-Enduser/", Search_EndUser_views.as_view(),
         name="SearchEndUserbyAdmin"),

    # Courier Company
    path("Search-Courier-Company/", Search_Courier_Company_views.as_view(),
         name="SearchCourierCompanybyAdmin"),

    # FAQ
    path("Search-FAQ/", Search_FAQ_views.as_view(),
         name="SearchFAQbyAdmin"),

    # Contact us
    path("Search-Contact-Us/", Search_Contact_Us_views.as_view(),
         name="SearchContactusbyAdmin"),

    # Support
    path("Search-Support-Ticket/", Search_Support_Ticket_views.as_view(),
         name="SearchSupportTicketbyAdmin"),

    # Notification
    path("Search-Notification/", Search_Notification_views.as_view(),
         name="SearchNotificationbyAdmin"),


    # Banner
    path("Search-Banner/", Search_Banner_views.as_view(),
         name="SearchBannerbyAdmin"),


    # Banner
    path("Search-Offer/", Search_Offer_views.as_view(),
         name="SearchOfferbyAdmin"),




    # *************************  Filter   *************************
]
