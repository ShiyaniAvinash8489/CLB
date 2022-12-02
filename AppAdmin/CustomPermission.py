"""
***************
    Packages 
***************
"""

# Permisson
from rest_framework import permissions

# Admin Models
from AppAdmin.models import (
    User,
)


"""
*********************************************************************************************************
                                        Custom Permission  
*********************************************************************************************************
"""


class AllowSuperAdminUser(permissions.BasePermission):

    def has_permission(self, request, view):
        if request.user.is_staff and not request.user.is_superuser:
            return False
        if not request.user.is_staff and not request.user.is_superuser:
            return False
        return True


class IsOwnerAndIsSuperAdmin(permissions.BasePermission):

    def has_permission(self, request, view):
        # print(
        #     f"\n\n\n\n\n Views:-  {view.kwargs} \n Request: - {request} \n\n\n ")
        if not request.user.is_staff and request.user.is_superuser:
            return True
        return request.user == User.objects.get(pk=view.kwargs['pk'])
