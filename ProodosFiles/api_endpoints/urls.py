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
    path("view_fo/", views.FolderViewAPIView.as_view(), name="view_fo"),
    path("fo/sharing/", views.ShareFolderAPIView.as_view(), name="fold_shar"),
    path("fo/star/", views.StarFolderAPIView.as_view(), name="star_folder_api"),
    path("fo/bin/", views.BinFolderAPIView.as_view(), name="bin_fo_api"),
    path("fo/del/", views.DeletePermAPIView.as_view(), name="delete_perm_api"),

    path('serve-dc-img/<uuid:file_id>/<str:image_name>/', views.serve_secure_doc_image, name='serve_img'),
    # your other routes

]