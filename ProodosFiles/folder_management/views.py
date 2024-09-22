import os
import shutil
from django.conf import settings
from django.http import Http404, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from uuid import UUID
from user_management.models import CustomUser
from .models import Folder, SharedFolder
from file_management.models import File, SharedFile
from file_management.views import get_file_or_404
from datetime import datetime

def apply_shared_permissions(folder):
    for subfolder in folder.subfolders.all():
        for usern in folder.access_list.all():
            subfolder.access_list.add(usern)
        subfolder.save()
        apply_shared_permissions(subfolder)  # Recursively apply to subfolders
    for file in folder.subfiles.all():
        for usern in folder.access_list.all():
            file.access_list.add(usern)
        file.save()

@login_required
def view_folder(request, folder_id: UUID):
    folder = get_file_or_404(Folder, item_id=folder_id)
    # if folder:
    #     apply_shared_permissions(folder)
    # if (folder.owner == request.user) or (SharedFolder.objects.filter(user=request.user, folder=folder).exists()) or (folder.access_list.contains(request.user)) or (folder.access_everyone == True):
    #     if (folder.owner == request.user):
    #         folder.access_count += 1
    #     folder.save()
    #     subfolders = folder.subfolders.all()
    #     files = folder.subfiles.all()
    #     all_folders = Folder.objects.filter(owner=request.user).all()
    #     print(all_folders)

    #     if request.method == 'POST':
    #         folder_name = request.POST.get('folder_name')
    #         new_folder = Folder.objects.create(name=folder_name, parent=folder, owner=request.user)
    #         new_folder.save()
    #         if folder.owner != request.user:
    #             if SharedFolder.objects.filter(shared_by=request.user, folder=folder).exists():
    #                 for sharing in SharedFolder.objects.filter(shared_by=request.user, folder=folder):
    #                     SharedFolder.objects.get_or_create(user=sharing.user, shared_by=request.user, folder=new_folder, role=sharing.role)
    #             SharedFolder.objects.get_or_create(user=folder.owner, folder=new_folder, shared_by=request.user, role=3)
    #         return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

    return render(request, 'files_folders.html ')# {'folder': folder, 'folders': subfolders, 'files': files, 'all_folders': all_folders})
    # raise Http404('You do not have permission to view this file')

def share_item_recursive(item, users, user):
    # If the item is a folder, share all subfolders and files
    if isinstance(item, Folder):
        for subfolder in item.subfolders.all():
            subfolder.access_list.add(users)
            try:
                SharedFolder.objects.create(
                        user=user,
                        folder=item,
                        shared_by=request.user
                    )
            except:
                pass
            share_item_recursive(subfolder, users, user)  # Recursively share subfolders
        for file in item.subfiles.all():
            try:
                SharedFile.objects.create(
                        user=user,
                        folder=item,
                        shared_by=user
                    )
            except:
                pass
            file.access_list.add(users)

@login_required
def share_folder(request, folder_id):
    from django.contrib import messages as messa
    folder_instance = get_object_or_404(Folder, id=folder_id)
    if folder_instance.is_editor(request.user.id):
        if folder_instance.access_everyone:
            messa.info(request, "This folder has already been shared with everyone but you can specify user permissions")
        if request.method == 'POST':
            print(request.POST)
            usernames = request.POST.get('usernames', '')
            share_with_everyone = request.POST.get('everyone', False)
            friend_to_share = request.POST.getlist('friends')
            role = request.POST.get('userRole', 1)
            print(role)
            print(request.POST)
            usernames = [username.strip() for username in usernames.split(',') if username.strip()]
            for friend in friend_to_share:
                usernames.append(CustomUser.objects.get(id=friend).username)
            print(usernames)
            messages = []
            if not share_with_everyone:
                if folder_instance.access_everyone:
                    messa.info(request, "This folder has been remove from everyone's view")
                folder_instance.access_everyone = False
                folder_instance.save()
                for username in usernames:
                    user = CustomUser.objects.filter(username=username).first()
                    folder_instance.access_list.add(user)
                    folder_instance.save()
                    if user and user != request.user:
                        try:
                            if SharedFolder.objects.filter(user=user, folder=folder_instance).exists():
                                shared_item = SharedFolder.objects.get(user=user, folder=folder_instance)
                                shared_item.shared_by = request.user
                                shared_item.role = role
                                shared_item.save()
                            else:
                                SharedFolder.objects.create(
                                    user=user,
                                    folder=folder_instance,
                                    shared_by=request.user,
                                    role=role
                                )
                            print("diddd")
                        except Exception as e:
                            print(e)
                        share_item_recursive(folder_instance, user, request.user)
                        messages.append(f'{folder_instance.name} shared with {user.username}')
                    else:
                        messages.append(f'Failed to share with {username} (invalid username or sharing with yourself).')
            else:
                folder_instance.access_everyone = True
                folder_instance.save()
                messages.append(f'{folder_instance.name} shared with everyone')
            return JsonResponse({'status': 'success', 'messages': messages})
    
    shared_list = SharedFolder.objects.filter(shared_by=request.user, folder=folder_instance)
    shared_with_everyone = folder_instance.access_everyone
    return render(request, 'share_item.html', {'item_type': 'Folder', 'item_name': folder_instance.name, 'item_id': folder_instance.id, "sharing_list": shared_list, "access_to_all": shared_with_everyone, 'item': folder_instance})


@login_required
def star(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id)

    if request.user != folder.owner:
        if not (folder.access_list.contains(request.user) or folder.access_everyone or SharedFolder.objects.filter(folder=folder, user=request.user).exists()):
            return HttpResponseForbidden("You are not permitted to star this folder as it is not yours")
        

    if folder.owner == request.user:
        if folder.starred:
            folder.starred = False
        else:
            folder.starred = True
    else:
        user = request.user
        if user.starred_folders.contains(folder):
            user.starred_folders.remove(folder)
            user.save()
        else:
            user.starred_folders.add(folder)
            user.save()
    folder.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))


@login_required
def bin(request, folder_id):
    folder = get_file_or_404(Folder, item_id=folder_id)

    if request.user != folder.owner:
        if not folder.has_perm(request.user.id):
            return HttpResponseForbidden("You cannot bin this folder as it is not yours")
        folder.deny_access(request.user.id)
    else:
        if not folder.binned:
            folder.binned = datetime.now()
            folder.save()
        else:
            if folder.parent:
                if not folder.parent.binned:
                    folder.binned = None
                    folder.save()
                else:
                    folder.parent = None
                    folder.binned = None
                    folder.save()
            else:
                folder.binned = None
                folder.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

@login_required
def delete_permanently(request, folder_id):
    folder = get_file_or_404(Folder, item_id=folder_id)
    if folder.owner == request.user:
        folder.delete()
        return redirect('binned_view')
    elif folder.has_perm(request.user.id):
        folder.deny_access(request.user.id)
        return redirect('binned_view')
    else:
        return redirect('binned_view')
    
@login_required
def copy_shared_folder(request, folder_id):
    folder_instance = get_object_or_404(Folder, id=folder_id)

    if not folder_instance.has_perm(request.user.id):
        return HttpResponseForbidden('You do not have access to this item')
    
    folder_directory = os.path.join(settings.MEDIA_ROOT, folder_instance.get_path())


    root_folder = Folder.objects.create(
        name=folder_instance.name,
        parent=None,
        owner=request.user
    )
    
    root_path = os.path.join(settings.MEDIA_ROOT, root_folder.get_path())
    shutil.copytree(folder_directory, root_path, dirs_exist_ok=True)

    for root, dirs, files in os.walk(folder_directory):
        # Calculate the relative path from the root of the unzipped directory
        relative_path = os.path.relpath(root, folder_directory)

    #     # Find or create the current parent folder in the database, starting from the root folder
        if relative_path != '.':
            parent_folder, created = Folder.objects.get_or_create(
                name=os.path.basename(root),
                parent=root_folder if relative_path == '.' else parent_folder,
                owner=request.user
            )
        else:
            parent_folder = root_folder

        # Create subfolders in the database
        for dir_name in dirs:
            Folder.objects.create(
                name=dir_name,
                parent=parent_folder,
                owner=request.user
            )

        # Create file entries in the database
        for file_name in files:
            file_path = os.path.join(root, file_name)
            relative_file_path = os.path.relpath(file_path, settings.MEDIA_ROOT)
            file_size = os.path.getsize(file_path)  # Get the file size in bytes

            # if not File.objects.filter(name=file_name, parent=parent_folder, owner=request.user).exists():
            #     base_name, extension = os.path.splitext(file_name)
            #     file_name = f"{base_name} (copy){extension}"
            # Create the file entry in the correct folder in the database
            File.objects.create(
                name=file_name,
                file=relative_file_path,
                owner=request.user,
                parent=parent_folder,
                size=file_size  # Set the file size
            )

    messages.success(request, "Folder has been successfully copied to Your Files")
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))