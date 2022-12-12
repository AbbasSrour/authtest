import jwt
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed

from authentication.models import CustomUser, UserSession
from authtest import settings


class CustomUserSerializer(serializers.ModelSerializer):
	password = serializers.CharField(write_only=True)

	class Meta:
		model = CustomUser
		fields = '__all__'


class LoginSerializer(serializers.Serializer):
	id = serializers.IntegerField(required=False)
	email = serializers.EmailField(required=False)
	username = serializers.CharField(required=True)
	password = serializers.CharField(
		write_only=True,
		required=True,
		style={'input_type': 'password'}
	)
	company = serializers.CharField(read_only=True)

	def validate(self, attrs):
		username = attrs.get('username', '')
		password = attrs.get('password', '')
		database = attrs.get('company', '')

		try:
			user = CustomUser.objects.get(username=username)
		except CustomUser.DoesNotExist:
			raise AuthenticationFailed('Invalid password or username')

		if not user.check_password(password):
			return AuthenticationFailed('Invalid username or password')
		if not user.is_active:
			return AuthenticationFailed('Not active')

		return user

	class Meta:
		model = CustomUser
		fields = '__all__'


class RefreshTokenSerializer(serializers.Serializer):
	refresh_token = serializers.CharField(required=True)

	def validate(self, attrs):
		refresh = attrs.get('refresh_token')

		data = jwt.decode(jwt=refresh, key=settings.SECRET_KEY,
		                  algorithms=settings.SIMPLE_JWT['ALGORITHM'],
		                  options={'verify_signature': True})
		return data


class UserSessionSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserSession
		fields = '__all__'
