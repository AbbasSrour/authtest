from dynamic_db_router import in_database
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.backend import RefreshTokenAuthenticationBackend, AccessTokenAuthenticationBackend
from authentication.models import UserSession, CustomUser
from authentication.serializers import LoginSerializer, RefreshTokenSerializer, CustomUserSerializer
from authentication.utils import user_has_valid_session, create_access_token, create_refresh_token, decode_token


class UserCompaniesApiView(APIView):
    authentication_classes = [AccessTokenAuthenticationBackend]
    permission_classes = [IsAuthenticated]

    def get(self, request: Request, username):
        arr = []
        try:
            CustomUser.objects.using('default').get(username=username)
            arr.append('default')
        except CustomUser.DoesNotExist:
            default = None

        try:
            CustomUser.objects.using('company1').get(username=username)
            arr.append('company1')
        except CustomUser.DoesNotExist:
            company1 = None

        return Response({'databases': arr}, status.HTTP_200_OK)


class UserLoginView(APIView):
    serializer_class = LoginSerializer
    authentication_classes = []
    permission_classes = []

    def post(self, req: Request):
        # If the client did not specify a company the database will default to 'default'
        database = req.data.get('database', 'default')
        req.data['database'] = database
        if database == 'default':
            database2 = 'company1'
        else:
            database2 = 'default'

        # validating that the license is not expired
        # is_valid, validation_code, last_validated_at, is_online, userCount = validate_license_key(KEYGEN_LICENSE)
        # if validation_code != 'VALID':
        # 	raise AuthenticationFailed('Expired License')

        # validating the user
        with in_database(database, read=True, write=True):
            serializer = self.serializer_class(data=req.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data

        ### Part1 checking the specified database
        db1_session = user_has_valid_session(database, user)
        if db1_session is not None:
            return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)

        ###Part2: check if the user is logged in the second database ###
        # check if a user exists in the second company
        try:
            user_company2 = CustomUser.objects.using(database2).get(username=user.username)
        except CustomUser.DoesNotExist:
            user_company2 = None

        if user_company2 is not None:
            db2_session = user_has_valid_session(database2, user_company2)
            if db2_session is not None:
                return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)

        # Creating the tokens with the user and the company in the payload
        try:
            data = CustomUserSerializer(instance=user, many=False).data
            access = create_access_token(data, database)
            refresh = create_refresh_token(data, database)
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Creating a session
        try:
            UserSession.objects.using(database).create(user_id=user.id, token=refresh)
        except:
            return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)

        return Response({'user': serializer.data, 'tokens': {'access_token': access, 'refresh_token': refresh}},
                        status=status.HTTP_200_OK)


class RefreshTokensApiView(APIView):
    serializer_class = RefreshTokenSerializer
    authentication_classes = [RefreshTokenAuthenticationBackend]
    permission_classes = [IsAuthenticated]

    def post(self, req: Request):
        serializer = CustomUserSerializer(instance=req.user, many=False)
        user = serializer.data

        database = req.META['database']
        access = create_access_token(user=user, database=database)
        print(decode_token(access))

        return Response({'access_token': access}, status=status.HTTP_200_OK)


class UserLogoutApiView(APIView):
    def post(self, request: Request, id):
        database = request.query_params.get('database', 'default')
        with in_database(database, read=True, write=True):
            try:
                UserSession.objects.get(user_id=id).delete()
            except UserSession.DoesNotExist:
                return Response({'error': 'User is not logged in'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(status=status.HTTP_200_OK)
