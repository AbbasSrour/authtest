from calendar import timegm
from datetime import datetime

import jwt
from dynamic_db_router import in_database
from rest_framework import status
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from authentication.models import UserSession, CustomUser
from authentication.serializers import LoginSerializer, RefreshTokenSerializer, CustomUserSerializer
from authtest import settings


def create_tokens(user, company: str):
	access = jwt.encode(
		algorithm=settings.SIMPLE_JWT.get('ALGORITHM'),
		key=settings.SECRET_KEY,
		payload={
			'user': user,
			'exp': timegm((datetime.utcnow() + settings.SIMPLE_JWT.get('ACCESS_TOKEN_LIFETIME')).utctimetuple())
		},
	)
	refresh = jwt.encode(
		algorithm=settings.SIMPLE_JWT.get('ALGORITHM'),
		key=settings.SECRET_KEY,
		payload={
			'user': user,
			'company': company,
			'exp': timegm((datetime.utcnow() + settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME')).utctimetuple())
		},
	)

	return {
		'access_token': str(access),
		'refresh_token': str(refresh),
	}


class UserCompaniesApiView(APIView):
	def get(self, request: Request, username):
		arr = []
		try:
			default = CustomUser.objects.using('default').get(username=username)
			arr.append('default')
		except CustomUser.DoesNotExist:
			default = None

		try:
			company1 = CustomUser.objects.using('company1').get(username=username)
			arr.append('company1')
		except CustomUser.DoesNotExist:
			company1 = None

		return Response({'companies': arr}, status.HTTP_200_OK)


class UserLoginView(APIView):
	serializer_class = LoginSerializer

	## todo
	##  this can be refactored into small functions
	##  to make it super easy to check against more
	##  than 2 databases
	def post(self, req: Request):
		# If the client did not specify a company the company will default to 'default'
		database = req.data.get('company', 'default')
		req.data['company'] = database

		# validating that the license is not expired
		# is_valid, validation_code, last_validated_at, is_online, userCount = validate_license_key(KEYGEN_LICENSE)
		# if validation_code != 'VALID':
		# 	raise AuthenticationFailed('Expired License')

		with in_database(database, read=True, write=True):
			# validating a user
			serializer = self.serializer_class(data=req.data)
			serializer.is_valid(raise_exception=True)
			user = serializer.validated_data

			# check if the user already has a session in the database
			try:
				old_session = UserSession.objects.get(user=user)
			except UserSession.DoesNotExist:
				old_session = None

			# verify that the old session is valid
			if old_session:
				try:
					check_old_session = jwt.decode(jwt=old_session.token, key=settings.SECRET_KEY,
					                               algorithms=settings.SIMPLE_JWT['ALGORITHM'],
					                               options={'verify_signature': True, "verify_exp": True})
				except:
					check_old_session = None

				# if old session is valid deny access, else delete the session
				if check_old_session is not None:
					return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)
				else:
					old_session.delete()

		###Part2: check if the user is logged in the second company ###
		# getting the second db name
		if database == 'default':
			database2 = 'company1'
		else:
			database2 = 'default'

		with in_database(database2, read=True, write=True):
			## check if the user is in the second company
			try:
				user_company2 = CustomUser.objects.get(username=user.username)
			except CustomUser.DoesNotExist:
				user_company2 = None

			if user_company2 is not None:
				## check if he has a session
				try:
					company_2_session = UserSession.objects.using(database2).get(user=user_company2)
				except UserSession.DoesNotExist:
					company_2_session = None

				## check if the session is valid
				if company_2_session is not None:
					try:
						check_company_2_session = jwt.decode(jwt=old_session.token, key=settings.SECRET_KEY,
						                                     algorithms=settings.SIMPLE_JWT['ALGORITHM'],
						                                     options={'verify_signature': True, "verify_exp": True})
					except:
						check_company_2_session = None

					# if old session in company 2 is valid deny access, else delete the session
					if check_company_2_session:
						return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)
					else:
						company_2_session.delete()

		# Creating the tokens with the user and the company in the payload
		try:
			data = CustomUserSerializer(instance=user, many=False).data
			tokens = create_tokens(data, database)
		except:
			return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)

		try:
			UserSession.objects.using(database).create(user_id=user.id, token=tokens['refresh_token'])
		except:
			return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)

		return Response({'user': serializer.data, 'tokens': tokens}, status=status.HTTP_200_OK)


class RefreshTokensApiView(APIView):
	serializer_class = RefreshTokenSerializer

	def post(self, req: Request):
		# validate the jwt
		token = req.data.get('refresh_token')
		serializer = self.serializer_class(data=req.data)
		serializer.is_valid(raise_exception=True)

		# get the data
		payload = serializer.validated_data
		database = payload.get('company')

		user = payload.get('user')
		username = user.get('username')

		# checking the database session
		with in_database(database, read=True, write=True):
			try:
				db_session = UserSession.objects.get(user__username=username)
			except:
				db_session = None

			# if no session exists in database log em out
			if db_session is None:
				return Response({'error': "Token doesn't exist in the database"})

			# if a session exists in the database and is valid log em out
			if db_session.token != token:
				try:
					check_db_token = jwt.decode(jwt=db_session.token, key=settings.SECRET_KEY,
					                            algorithms=settings.SIMPLE_JWT['ALGORITHM'],
					                            options={'verify_signature': True, "verify_exp": True})
				except:
					check_db_token = None

				# old session is still valid deny him access and log em out
				if check_db_token is not None:
					return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)
				# old session is not valid so delete it and replace it with this token
				else:
					db_session.delete()
					UserSession.objects.create(token=token, user_id=user.get('id'))

		# getting the second db name
		if database == 'default':
			database2 = 'company1'
		else:
			database2 = 'default'

		# Part 2: checking the second database
		with in_database(database2, read=True, write=True):
			# checking the user exists there
			try:
				user_in_com2 = CustomUser.objects.get(username=username)
			except CustomUser.DoesNotExist:
				user_in_com2 = None

			# user exists there! check if he has a session
			if user_in_com2 is not None:
				try:
					comp2_session = UserSession.objects.get(user_id=user_in_com2.id)
				except UserSession.DoesNotExist:
					comp2_session = None

				# He has a session, check that it is valid
				if comp2_session is not None:
					try:
						check_comp2_token = jwt.decode(jwt=comp2_session.token, key=settings.SECRET_KEY,
						                               algorithms=settings.SIMPLE_JWT['ALGORITHM'],
						                               options={'verify_signature': True, "verify_exp": True})
					except:
						check_comp2_token = None

				# It is valid! Log em out
				if check_comp2_token:
					return Response({'error': 'Already logged in'}, status=status.HTTP_403_FORBIDDEN)

		# Everything is fine generate the new access token
		tokens = create_tokens(user=user, company=database)

		return Response({'access_token': tokens.get('access_token')}, status=status.HTTP_200_OK)


class UserLogoutApiView(APIView):
	def post(self, request: Request, id):
		database = request.query_params.get('database', 'default')
		with in_database(database, read=True, write=True):
			try:
				UserSession.objects.get(user_id=id).delete()
			except UserSession.DoesNotExist:
				return Response({'error': 'User is not logged in'}, status=status.HTTP_400_BAD_REQUEST)
		return Response(status=status.HTTP_200_OK)
