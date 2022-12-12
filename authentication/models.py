# Create your models here.

from django.contrib.auth.models import AbstractUser
from django.contrib.sessions.base_session import AbstractBaseSession
from django.db import models


class CustomUser(AbstractUser):
	email = models.EmailField(unique=True)
	photo = models.ImageField(blank=True, null=True)
	language = models.CharField(max_length=255, default='en-US')
	pinCode = models.BigIntegerField(unique=True, null=True, blank=True)

	USERNAME_FIELD = 'username'
	REQUIRED_FIELDS = []


class CustomSession(AbstractBaseSession):
	user = models.ForeignKey(
		CustomUser, on_delete=models.PROTECT, null=True, blank=True)

	def __str__(self):
		return self.session_key


class UserSession(models.Model):
	user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, null=True, blank=True, unique=True)
	token = models.TextField(null=True, blank=True)

	def __str__(self):
		return self
