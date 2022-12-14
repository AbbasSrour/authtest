from django.urls import path

from authentication.views import UserLoginView, RefreshTokensApiView, UserCompaniesApiView

urlpatterns = [
	path('login/', UserLoginView.as_view()),
	path('refresh/', RefreshTokensApiView.as_view()),
	path('companies/<str:username>', UserCompaniesApiView.as_view())
]
