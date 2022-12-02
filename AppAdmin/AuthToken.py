import jwt
from AppAdmin.models import User
from django.conf import settings


def DecodeToken(token):

    Bearer = str(token)
    jwt_token = Bearer.replace("Bearer ", "")

    payload = jwt.decode(jwt_token, settings.SECRET_KEY,
                         algorithms="HS256")

    UserId = User.objects.get(id=payload["user_id"]).id

    return UserId
