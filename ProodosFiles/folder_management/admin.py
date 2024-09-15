from django.contrib import admin
from .models import Folder, SharedFolder
# Register your models here.
admin.site.register(Folder)
admin.site.register(SharedFolder)