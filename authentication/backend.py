import json

import jwt
from rest_framework import authentication
from rest_framework.exceptions import AuthenticationFailed

from authentication.models import CustomUser
from authentication.utils import decode_token_unsafe, user_has_valid_session, decode_token


class AccessTokenAuthenticationBackend(authentication.BaseAuthentication):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Get the authorization header from the request
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        if not auth_header:
            raise AuthenticationFailed('No Authorization token provided')

        # Get the Authorization token
        token = auth_header.split()[1]

        if not token:
            raise AuthenticationFailed('No Authorization token provided')

        # Check the JWT token provided by the user
        try:
            payload = decode_token_unsafe(token)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Authorization token expired')
        except jwt.DecodeError:
            raise AuthenticationFailed('Decode error authorization token is invalid')
        except:
            raise AuthenticationFailed('Authorization token is invalid')

        try:
            user = payload.get('user')
            database = payload.get('database')
            request.META['database'] = database
        except:
            return AuthenticationFailed('System error')

        # If the JWT is valid, return the corresponding user object
        return self.get_user(user['id'], database), token

    def get_user(self, user_id, database):
        try:
            print(user_id)
            user = CustomUser.objects.using(database).get(pk=user_id)
            print(user)
            return user
        except CustomUser.DoesNotExist:
            return None


class RefreshTokenAuthenticationBackend(authentication.BaseAuthentication):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # Get the authorization header from the request
        auth_header = request.META.get('HTTP_AUTHORIZATION')

        if not auth_header:
            raise AuthenticationFailed('No Authorization token provided')

        # Get the Authorization token
        token = auth_header.split()[1]

        if not token:
            raise AuthenticationFailed('No Authorization token provided')

        # Check the JWT token provided by the user
        try:
            payload = decode_token_unsafe(token)
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Authorization token expired')
        except jwt.DecodeError:
            raise AuthenticationFailed('Decode error authorization token is invalid')
        except:
            raise AuthenticationFailed('Authorization token is invalid')

        try:
            user_id = payload.get('user')['id']
            database = payload.get('database')
            request.META['database'] = database
        except:
            return AuthenticationFailed('System error')

        # If the JWT is valid, return the corresponding user object
        user = self.get_user(user_id, database)
        if user is None:
            raise AuthenticationFailed('Authentication error user doesn\'t exist')

        # getting the second db name
        if database == 'default':
            database2 = 'company1'
        else:
            database2 = 'default'

        # Validate the user session
        db_session = user_has_valid_session(database, user)

        if db_session is None or db_session != token:
            raise AuthenticationFailed("Token doesn't exist in the database")

        # Part 2: checking the second database
        try:
            user_in_com2 = CustomUser.objects.using(database2).get(username=user)
        except CustomUser.DoesNotExist:
            user_in_com2 = None

        if user_in_com2:
            db2_session = user_has_valid_session(database=database2, user=user_in_com2)
            if db2_session is not None:
                raise AuthenticationFailed('Already logged in')

        return user, token

    def get_user(self, user_id, database):
        try:
            return CustomUser.objects.using(database).get(pk=user_id)
        except CustomUser.DoesNotExist:
            return None
