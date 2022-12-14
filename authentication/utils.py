from calendar import timegm
from datetime import datetime

import jwt
from dynamic_db_router import in_database

from authentication.models import UserSession
from authtest import settings


def create_access_token(user, database):
    access = jwt.encode(
        algorithm=settings.SIMPLE_JWT.get('ALGORITHM'),
        key=settings.SECRET_KEY,
        payload={
            'user': user,
            'database': database,
            'exp': timegm((datetime.utcnow() + settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME')).utctimetuple())
        },
    )
    return access


def create_refresh_token(user, database):
    refresh = jwt.encode(
        algorithm=settings.SIMPLE_JWT.get('ALGORITHM'),
        key=settings.SECRET_KEY,
        payload={
            'user': user,
            'database': database,
            'exp': timegm((datetime.utcnow() + settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME')).utctimetuple())
        },
    )
    return refresh


def decode_token(token):
    try:
        payload = jwt.decode(jwt=token, key=settings.SECRET_KEY,
                             algorithms=settings.SIMPLE_JWT['ALGORITHM'],
                             options={'verify_signature': True, "verify_exp": True})
    except jwt.exceptions.InvalidTokenError:
        return None
    return payload


def decode_token_unsafe(token):
    payload = jwt.decode(jwt=token, key=settings.SECRET_KEY,
                         algorithms=settings.SIMPLE_JWT['ALGORITHM'],
                         options={'verify_signature': True, "verify_exp": True})
    return payload


def user_has_valid_session(database, user):
    with in_database(database, read=True, write=True):
        # check if the user already has a session in the database
        try:
            old_session = UserSession.objects.get(user=user)
        except UserSession.DoesNotExist:
            old_session = None

        # verify that the old session is valid
        if old_session:
            check_old_session = decode_token(old_session.token)

            # if old session is valid deny access, else delete the session
            if check_old_session is not None:
                return old_session.token
            else:
                old_session.delete()

    return None
