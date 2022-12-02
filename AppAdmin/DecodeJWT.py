"""
******************
    Packages 
******************
"""
# Admin Models
from AppAdmin.models import (
    User,
)

# Json Web Token
import jwt

# Import Settings
from django.conf import settings

# Decouple
from decouple import config


"""
************************************
                Decode JWT 
************************************
"""


def DecodeJWT(Token):
    Bearer = str(Token)
    jwt_token = Bearer.replace("Bearer ", "")

    payload = jwt.decode(jwt_token, settings.SECRET_KEY,
                         algorithms=config("JWT_ALGORITHMS"))

    UserId = User.objects.get(id=payload["user_id"]).id

    return UserId
