from django.urls import path
from . import views

urlpatterns = [
    path('upload/<uuid:folder_id>/', views.upload_file, name='upload_file'),
    path('preview/<uuid:file_id>/', views.preview_file, name='preview_file'),
    path('star/<uuid:file_id>/', views.star, name='star_file'),
    path('share/<uuid:file_id>/', views.share_file, name='share_file'),
    path('serve-signed/<str:signed_value>/', views.serve_signed_file, name='serve_signed_file'),
    path('bin/<uuid:file_id>/', views.bin, name="bin_file"),
    path('delete-file/<uuid:file_id>/', views.delete_permanently, name="delete_file"),
    path('unzip/<uuid:file_id>/', views.unzip, name='unzip_file'),
    path('send-zip/<uuid:folder_id>/', views.zip_folder, name='zip_folder'),
    path('copy-shared-file/<uuid:file_id>/', views.copy_shared_file, name='copy_shared_file'),
    path('serve-dc-img/<uuid:file_id>/<str:image_name>/', views.serve_secure_doc_image, name='serve_img'),
    path('changeRole/', views.change_role, name="change_role"),
    path('removeAcces/', views.remove_access, name="remove_access"),
]