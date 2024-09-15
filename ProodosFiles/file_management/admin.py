from django.contrib import admin
from .models import File, SharedFile

# Register your models here.
admin.site.register(File)
admin.site.register(SharedFile)