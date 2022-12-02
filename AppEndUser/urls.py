"""
*************************************
        Imported Packages 
*************************************
"""

# By Default

from django.contrib import admin
from django.urls import path, include


# App End User
from AppEndUser.views import (

    # End user Login
    EndUserLogin_View,

    # Verify OTP
    VerifyOTP_Views,

    # Sender & Receiver Address
    Sender_Address_Create_Views,
    Receiver_Address_Create_Views,
    List_Sender_Receiver_Address_Views,
    Delete_Soft_Address_views,
    Update_Receiver_Address_Views,
    Get_Singal_AddressBook_views,

    # Pincode Search
    Check_CLB_PickUp_Views,
    Check_Delivery_pincode_Views,

    # Booking Slot
    End_Booking_Slot_view,

    # CLB Review
    POst_CLB_Review_Views,
    List_CLB_Review_View,

    # Courier Company Review
    Post_Courier_Company_Review_Views,
    List_Courier_Company_Review_View,


    # Compare Price
    Compare_Price_View,

    # Support Ticket
    Create_Support_Ticket_Views,
    List_Open_Support_Ticket_Views,
    List_In_Progress_Support_Ticket_Views,
    List_Closed_Support_Ticket_Views,
    Get_SupportTicket_views,


    # Banner
    List_Active_Banner_EndUserViews,

    # Offer
    List_Active_Offer_EndUserViews,
    Get_Offer_EndUserViews,
    PromoCode_Get_View,

    # Card
    Create_Card_Details_Views,
    Update_Card_Details_Views,
    List_Card_Details_Views,
    Delete_Hard_Card_Details_views,
    Get_Singal_Card_Details_views,

    # Order
    Create_EndUser_Order_Views,
    List_Order_EndUser_Views,


)


"""
**************************************************************************
                            ULRS
**************************************************************************
"""

urlpatterns = [
    # End User Login
    path("EndUserLogin/", EndUserLogin_View.as_view(), name="End_User_Login"),

    # Vefiry OTP
    path("Verify_OTP/", VerifyOTP_Views.as_view(), name="Verify_OTP"),

    # ************** Sendeer & Receiver Address *****************
    path("CreateSenderAddress/", Sender_Address_Create_Views.as_view(),
         name="Create_Sender_Address"),
    path("CreateReceiverAddress/", Receiver_Address_Create_Views.as_view(),
         name="Create_Receiver_Address"),

    path("List_Address_book/",
         List_Sender_Receiver_Address_Views.as_view(), name="ListAddressBook"),
    path("Soft-Delete-Address-book/<int:pk>/",
         Delete_Soft_Address_views.as_view(), name="SoftDeleteAddressBook"),

    path("Update-Address-book/<int:pk>/",
         Update_Receiver_Address_Views.as_view(), name="UpdateAddressBook"),
    path("Get-Single-AddressBook/<int:pk>/",
         Get_Singal_AddressBook_views.as_view(), name="GetSongleAddressbook"),

    # ************************* Pincode *************************
    path("Search_PickUp_Pincode/<int:pincode>/",
         Check_CLB_PickUp_Views.as_view(), name="SearchPickUp-Pincode"),
    path("Search_Delivery_Pincode/<int:pincode>/",
         Check_Delivery_pincode_Views.as_view(), name="SearchDelivery-Pincode"),


    # ************************* Booking Slot *************************
    path("Select_PickUp_Slot/", End_Booking_Slot_view.as_view(),
         name="SelectPickUpSlot"),


    # ************************* Review CLB & Courier Company *************************
    path("CLB-Review-enduser/", POst_CLB_Review_Views.as_view(),
         name="CLBReviewEnduser"),
    path("List-CLB-Review-enduser_or_admin/",
         List_CLB_Review_View.as_view(), name="listCLBREviews"),
    path("post-Courier-Company-Review-enduser/", Post_Courier_Company_Review_Views.as_view(),
         name="Courier_CompanyReviewEnduser"),
    path("List-Courier-Company-Review-enduser_or_admin/",
         List_Courier_Company_Review_View.as_view(), name="listCourier_CompanyREviews"),
    path("Compare_Price/<str:FromPincode>/<str:ToPincode>/<str:ShipmentType>/<int:Weight>/",
         Compare_Price_View.as_view(), name="ComparePriceList"),

    # ************************* Support Ticket *************************
    path("Create-Support-Ticket-enduser/",
         Create_Support_Ticket_Views.as_view(), name="CreateSupportTicket"),
    path("List-Open-Ticket/", List_Open_Support_Ticket_Views.as_view(),
         name="ListOpenTicketEndUser"),
    path("List-In_Progress-Ticket/", List_In_Progress_Support_Ticket_Views.as_view(),
         name="ListIn_ProgressTicketEndUser"),
    path("List-Closed-Ticket/", List_Closed_Support_Ticket_Views.as_view(),
         name="ListIn_ProgressTicketEndUser"),
    path("Get-Ticket-Enduser/<int:pk>/", Get_SupportTicket_views.as_view(),
         name="GetSUpportTicketEndUser"),


    # ************************* Banner *************************
    path("EndUser-Active-Banner-List/",
         List_Active_Banner_EndUserViews.as_view(), name="EndUserActiveBannerList"),


    # ************************* Offer *************************
    path("EndUser-Active-Offer-List/",
         List_Active_Offer_EndUserViews.as_view(), name="EndUserActiveOfferList"),
    path("Get-Offer-Details/<int:pk>/",
         Get_Offer_EndUserViews.as_view(), name="GetOfferDetails"),
    path("Check-promocode/<str:coupon_code>/<str:Purchase_Amount>/", PromoCode_Get_View.as_view(),
         name="CheckPromoCodeenduser"),

    # ************************* Card Details *************************
    path("Create_Card_Details_endUser/",
         Create_Card_Details_Views.as_view(), name="CreateCardDetailsEnduser"),

    path("List_Card_Details/",
         List_Card_Details_Views.as_view(), name="ListCardDetails"),
    path("Hard-Delete-Card_Details/<int:pk>/",
         Delete_Hard_Card_Details_views.as_view(), name="HardDeleteCardDetails"),

    path("Update-Card_Details/<int:pk>/",
         Update_Card_Details_Views.as_view(), name="UpdateCardDetails"),
    path("Get-Single-Card_Details/<int:pk>/",
         Get_Singal_Card_Details_views.as_view(), name="GetSingleCardDetails"),

    # ************************* Order Details *************************

    path("Create-Order-Details/",
         Create_EndUser_Order_Views.as_view(), name="CreateDetailsEndUser"),
    path("List-Order-Enduser/", List_Order_EndUser_Views.as_view(),
         name="ListOrderEndUSer")

]
