"""
Imported Packeges
"""

# By Default
from pathlib import Path

# Decouple for Hiding all Credentials
from decouple import config


# Date & Time
from datetime import timedelta

# System
import os

# translations
from django.utils.translation import gettext_lazy as _


"""
******************************************************************************************************************
                                    Basic Settings
******************************************************************************************************************
"""

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.0/howto/deployment/checklist/


"""
*************************************
        Secret Key & Debug
*************************************
"""

SECRET_KEY = config("SECRET_KEY")


DEBUG = config("DEBUG")


"""
*************************************
        ALLOWED_HOSTS
*************************************
"""

ALLOWED_HOSTS = []


# *************************************
#          INSTALLED_APPS
# *************************************

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Rest Framework
    'rest_framework',

    # Authentication Token
    'rest_framework.authtoken',

    # Cors Headers
    "corsheaders",

    # Swagger
    'drf_yasg',

    # Simple JWT
    'rest_framework_simplejwt',

    # Admin App
    "AppAdmin.apps.AppadminConfig",

    # Agent App
    "AppAgent.apps.AppagentConfig",

    # EndUser App
    "AppEndUser.apps.AppenduserConfig",

]


# *************************************
#             MIDDLEWARE
# *************************************


MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'ProjectCLB.urls'


"""
**********************************************
                    Core Header
**********************************************
"""

CORS_ORIGIN_ALLOW_ALL = True

CORS_ALLOW_METHODS = [
    "DELETE",
    "GET",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
]

APPEND_SLASH = False


# *************************************
#             TEMPLATES
# *************************************


TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': ["templates"],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


# *************************************
#             WSGI_APPLICATION
# *************************************

WSGI_APPLICATION = 'ProjectCLB.wsgi.application'


# *************************************
#             DATABASES
# *************************************

DATABASES = {
    'default': {
        'ENGINE': config("DB_ENGINE"),
        'NAME': config("DB_NAME"),
        'USER': config("DB_USER"),
        'PASSWORD': config("DB_PASSWORD"),
        'HOST': config("DB_HOST"),
        'PORT': config("DB_PORT"),
    }
}


# Git Hub Work Flow
if os.environ.get('GITHUB_WORKFLOW'):
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'github_actions',
            'USER': 'postgres',
            'PASSWORD': 'postgres',
            'HOST': '127.0.0.1',
            'PORT': '5432',
        }
    }

# Password validation
# https://docs.djangoproject.com/en/4.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


"""
*************************************
            Time Zone
*************************************
"""


LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'
# TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


"""
*************************************
             Static Files
*************************************
"""

# ******************  Static   ******************
STATIC_ROOT = os.path.abspath(os.path.join(
    BASE_DIR, 'ProjectCLB', 'static'))

STATIC_URL = '/static/'

# STATIC_ROOT = os.path.join(BASE_DIR, 'static/')

STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'static/')

]

# ******************  Media   ******************
MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, "static/media")
# STATIC_ROOT = os.path.join(BASE_DIR, "staticfile")


"""
*************************************
        DEFAULT_AUTO_FIELD
*************************************
"""


# Default primary key field type
# https://docs.djangoproject.com/en/4.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


"""
******************************************************************************************************************
                                    Customs Settings
******************************************************************************************************************
"""


"""
*************************************
    Authentication Custom User Model
*************************************
"""

AUTH_USER_MODEL = "AppAdmin.User"


"""
*************************************
            Rest Frame Work
*************************************
"""


REST_FRAMEWORK = {

    # Filter
    'DEFAULT_FILTER_BACKENDS': ['django_filters.rest_framework.DjangoFilterBackend'],

    # Globally Authentication - JWT
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],

    # Permission Class
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ]
}


"""
*************************************
            Simple JWT
*************************************
"""

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=59),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,

}


"""
*************************************
            Email Config
*************************************
"""

EMAIL_BACKEND = config("EMAIL_BACKEND")
EMAIL_USE_TLS = config("EMAIL_USE_TLS")
EMAIL_HOST = config("EMAIL_HOST")
EMAIL_PORT = config("EMAIL_PORT")
EMAIL_HOST_USER = config("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = config("EMAIL_HOST_PASSWORD")


"""
*************************************
                Swagger
*************************************
"""

SWAGGER_SETTINGS = {
    'DEFAULT_INFO': 'testproj.urls.swagger_info',
    'JSON_EDITOR': True,
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'in': 'header',
            'name': 'Authorization'
        },
    }
}


"""
*************************************
                Twilio
*************************************
"""

# Project
TWILIO_SID = config("TWILIO_SID")

# Auth Token
TWILIO_AUTH_TOKEN = config("TWILIO_AUTH_TOKEN")

# Verify ID
TWILIO_SERVICE_ID = config("TWILIO_SERVICE_ID")


"""
*************************************
Handling Redirects to Mobile App & The Frontend
*************************************
"""


FRONTEND_URL = config("FRONTEND_URL")
APP_SCHEME = config("APP_SCHEME")


"""
*************************************
            Encrypt Decrypt
*************************************
"""

ENCRYPT_KEY = config("ENCRYPT_KEY")


"""
*************************************
            Redis
*************************************
"""


# Settings
CACHES = {
    "default": {
        "BACKEND": config("REDIS_BACKEND"),
        "LOCATION": config("REDIS_LOCATION"),
        "OPTIONS": {
            "CLIENT_CLASS": config("REDIS_CLIENT_CLASS"),
        },
        "KEY_PREFIX": "On_Demand"
    }
}
