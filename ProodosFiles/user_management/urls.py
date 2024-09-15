from django.contrib.auth import views as auth_views
from django.urls import path
from . import views

urlpatterns = [
    path('friends/', views.friends_list, name='friends_list'),
    path('friends/remove/<uuid:friend_id>/', views.remove_friend, name='remove_friend'),
    path('friends/send_request/', views.send_friend_request, name='send_friend_request'),
    path('friends/accept_request/<uuid:request_id>/', views.accept_friend_request, name='accept_friend_request'),
    path('friends/decline_request/<uuid:request_id>/', views.decline_friend_request, name='decline_friend_request'),
    path("register/", views.register, name="register"),
    path('login/', views.login, name='login_to'),
    path('logout/', views.log_out, name='logout'),
    path('activate/',  views.activate, name='activate'),
    path('password-reset/<uidb64>/<token>/',  views.password_reset, name='password_reset_f'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
]