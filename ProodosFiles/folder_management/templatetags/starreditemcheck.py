from django import template

from file_management.models import File, SharedFile
from folder_management.models import Folder, SharedFolder

register = template.Library()

@register.filter
def starred_item(item, request):
    if request.user.starred_files.contains(item) or request.user.starred_folders.contains(item):
        return True
    return False

@register.filter
def can_move_item(item, request):
    try:
        item = File.objects.get(id=item.id)
        if item.is_editor(request.user.id):
            return True
        return False
    except File.DoesNotExist:
        item = Folder.objects.get(id=item.id)
        if item.is_editor(request.user.id):
            return True
        return False
    
@register.filter
def has_all_rights(item, request):
    return item.is_editor(request.user.id)