from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed, ValidationError

from authentication.models import CustomUser, UserSession
from authentication.utils import decode_token


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
	database = serializers.CharField(read_only=True)

	def validate(self, attrs):
		username = attrs.get('username', '')
		password = attrs.get('password', '')
		database = attrs.get('database', '')

		try:
			user = CustomUser.objects.using(database).get(username=username)
		except CustomUser.DoesNotExist:
			raise ValidationError('Invalid password or username', code=400)

		if not user.check_password(password):
			raise ValidationError('Invalid username or password', code=400)
		if not user.is_active:
			raise ValidationError('Not active', code=403)

		return user

	class Meta:
		model = CustomUser
		fields = '__all__'


class RefreshTokenSerializer(serializers.Serializer):
	refresh_token = serializers.CharField(required=True)

	def validate(self, attrs):
		refresh = attrs.get('refresh_token')

		data = decode_token(refresh)
		return data


class UserSessionSerializer(serializers.ModelSerializer):
	class Meta:
		model = UserSession
		fields = '__all__'
