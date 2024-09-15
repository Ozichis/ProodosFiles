from django.urls import path
from . import views

urlpatterns = [
    path('sign-up/', views.RegisterView.as_view(), name='sign_up_api'),
    path('verify/', views.VerifyEmailView.as_view(), name='verify_api'),
    path('login/', views.LoginView.as_view(), name='login'),
    # your other routes
]