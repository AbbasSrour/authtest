from django.contrib import admin

from authentication.models import CustomUser, UserSession

# Register your models here.
admin.register(CustomUser)
admin.register(UserSession)
