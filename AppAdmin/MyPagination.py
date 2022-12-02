"""
******************
    Packages
******************
"""

from rest_framework.pagination import PageNumberPagination


"""
******************************************************
                    Pagination Class
******************************************************
"""


class Pagination_Page_50(PageNumberPagination):
    page_size = 100
