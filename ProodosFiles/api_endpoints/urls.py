from django.urls import path
from . import views

urlpatterns = [
    path('sign-up/', views.RegisterView.as_view(), name='sign_up_api'),
    path('verify/', views.VerifyEmailView.as_view(), name='verify_api'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('upload_file/', views.FileUploadView.as_view(), name='api_upload_file'),
    path('download_file/', views.download_file, name="download_f_api"),
    path('download-signed/<str:signed_value>/', views.download_signed_file, name='serve_download_file'),
    path('resender/', views.ResendVerificationEmailView.as_view(), name="resend_verifi"),
    path("rest-pswd/", views.PasswordResetAPIView.as_view(), name="reset_paswrd"),
    path("forgot-pass/", views.PasswordResetRequestAPIView.as_view(), name="forgot_passw"),
    path("create-f/", views.FolderCreateAPIView.as_view(), name="create_fo"),
    # your other routes
]