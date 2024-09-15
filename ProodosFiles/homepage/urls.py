from django.urls import path
from django.views.generic.base import RedirectView
from . import views
from file_management.views import rename_item, move_item

urlpatterns = [
    path('home/', views.home, name="homepage"),
    path('all/', views.all_files, name='my_files'),
    path("", RedirectView.as_view(url="/home/"), name="redirected_homepage"),
    path("shared-with-me/", views.view_shared_items, name="shared_items"),
    path('starred/', views.starred_items, name='starred_items'),
    path('binned/', views.binned_view, name="binned_view"),
    path('item/rename/', rename_item, name="rename_item"),
    path('item/move/<str:destination_item_id>/<uuid:item_id>/', move_item, name="move_item"),
    path('redir/', views.go_back, name="go_back"),
]
