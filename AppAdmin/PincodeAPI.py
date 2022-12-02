"""
**************
    Packages 
**************
"""

# Decouple for Calling Env. Variable from Env File
from decouple import config

# Requests for Calling API
import requests

"""
********************************************************************************************************
                        Pincode Logic 
********************************************************************************************************
"""


def Indian_Post_Pincode(Pincode_Number):

    PostAPI = config("PINCODE_API")+str(Pincode_Number)

    result = requests.get(PostAPI).json()[0]["PostOffice"]
    areaList = []
    for i in result:
        areaList.append(i["Name"])

    return areaList
