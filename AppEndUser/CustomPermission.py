"""
*********************
        Packages 
*********************
"""

# Persmisison
from rest_framework import permissions


# Error handling
from rest_framework.exceptions import NotAuthenticated

# Translation
from django.utils.translation import gettext_lazy as _

# Parser & Status
from rest_framework import status


"""
**********************************************************************************
                        Custom Permission Foe EndUser  
**********************************************************************************
"""


class OnlyEndUser(permissions.BasePermission):

    def has_permission(self, request, view):
        try:

            if request.user.user_type == "EndUser":
                return True
            # if not request.user.is_staff and not request.user.is_superuser:
            #     return False
            return False
        except Exception:
            raise NotAuthenticated(
                detail={"code": 401, 'message': _("You are unauthorized")}, code=status.HTTP_401_UNAUTHORIZED)
