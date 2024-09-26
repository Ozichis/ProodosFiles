import base64
import hashlib
import io
from mimetypes import guess_type
import mimetypes
import os
import re
import shutil
import uuid
import zipfile

from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse, HttpResponseForbidden, HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.contrib.auth.decorators import login_required

from cryptography.fernet import Fernet

from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.urls import reverse
from django.utils.http import urlencode
from datetime import datetime, timedelta

import requests.adapters

from file_management.models import File
from folder_management.models import SharedFolder
from user_management.models import CustomUser
from .models import FileEncryption, Folder, SharedFile
import chardet


@login_required
def upload_file(request, folder_id=None):
    return render(request, 'upload_files.html', {})

def notify_sharing(file, user: CustomUser):
    email = user.email




@login_required
def preview_file(request, file_id):
    # Get the file object
    file = get_object_or_404(File, id=file_id)

    # Check if the user has permission to access the file
    if not file.has_perm(request.user.id):
        return HttpResponseForbidden("You do not have permission to access this file.")
    document = False
    # Determine the file type
    file_extension = os.path.splitext(file.file.name)[1].lower()
    print(file_extension)
    import filetype
    mime_type, encoding = mimetypes.guess_type(file.get_full_path())
    if mime_type is None:
        file_type = 'unknown'
    else:
        if mime_type.startswith("image/"):
            file_type = 'image'
        elif mime_type == "application/pdf":
            file_type = 'document'
        elif file_extension in ['.docx']:
            document = True
            file_type = 'office'
        elif mime_type.startswith("video/"):
            file_type = 'video'
        elif mime_type.startswith("audio/"):
            file_type = "audio"
        elif not is_binary_file(apply_correct_path(file.get_full_path())):
            file_type = 'text'
            document = True
        else:
            messages.error(request, "Unsupported file type for inline viewing. ")
            return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
    context = {
        'file': file,
        'file_type': file_type,
        'file_url': generate_signed_url(file, request.user),
    }

    if document:
        if file_type == "office":
            import mammoth
            encryptor = Fernet(settings.FILE_ENCRYPTION_KEY)
            docx_file = open(file.file.path, 'rb')
            decrypted_data = encryptor.decrypt(docx_file.read())
            with io.BytesIO(decrypted_data) as decrypted_data:
                html_content = mammoth.convert_to_html(decrypted_data).value

                secure_html = process_html_for_secure_images(html_content, file_id)
                context['content'] = secure_html
        elif file_type == "text":
            with open(file.file.path, 'r') as doc:
                context['content'] = doc.read()
    return render(request, 'file_preview.html', context)

@login_required
def serve_signed_file(request, signed_value):
    signer = TimestampSigner()
    try:
        # Extract expiry time from the query parameters
        expiry_seconds = request.GET.get('expiry')
        
        # Validate the signed value and ensure the link hasn't expired
        original_value = signer.unsign(signed_value, max_age=float(expiry_seconds))
        file_id, user_id = original_value.split(':')
        
        # Ensure the user is the owner or has access
        file = get_object_or_404(File, id=file_id)
        if file.has_perm(request.user.id):
            encrypted_file_path = apply_correct_path(file.get_full_path())
            # with open(encrypted_file_path, 'rb') as f:
            #     encrypted_content = f.read()
            decryptor = Fernet(settings.FILE_ENCRYPTION_KEY)
            # decrypted_content = decryptor.decrypt(encrypted_content)
            # # print(decrypted_content)
            # # Serve the decrypted file for inline viewing (in-memory)
            # response = FileResponse(decrypted_content, content_type='application/octet-stream')
            # response['Content-Disposition'] = f'inline; filename="{file.name}"'
            # return response
            with open(encrypted_file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()
                decrypted_data = decryptor.decrypt(encrypted_data)

            # Guess the MIME type based on file extension
            mime_type, _ = guess_type(file.name)

            # Serve the decrypted content inline
            response = HttpResponse(decrypted_data, content_type=mime_type)
            response['Content-Disposition'] = f'inline; filename={file.name}'
            return response
        else:
            return HttpResponseForbidden("You do not have permission to access this file.")
     
    except SignatureExpired:
        return HttpResponseForbidden("This link has expired.")
    
    except BadSignature:
        return HttpResponseForbidden("Invalid URL.")

# @login_required
# def share_file(request, file_id):
#     file_instance = get_object_or_404(File, id=file_id)
#     if file_instance.is_editor(request.user.id):
        
#         if file_instance.access_everyone:
#             return render(request, 'share_item.html', {'item_type': 'file', 'item_name': file_instance.name, 'item_id': file_instance.id, 'user': request.user, 'messages': ['This file has already been shared by everyone']})
#         if request.method == 'POST':
#             usernames = request.POST.get('usernames', '')
#             role = request.POST.get('userRole', '1')
#             share_with_everyone = request.POST.get('everyone', False)
#             friend_to_share = request.POST.getlist('friends')
            
#             usernames = [username.strip() for username in usernames.split(',') if username.strip()]
            
#             for friend in friend_to_share:
#                 usernames.append(CustomUser.objects.get(id=friend).username)
#             print(usernames)

#             messages = []
#             if not share_with_everyone:
#                 for username in usernames:
#                     user = CustomUser.objects.filter(username=username).first()
#                     print(file_instance)
#                     file_instance.access_list.add(user)
#                     print(file_instance.access_list.all())
#                     file_instance.save()
#                     if user and user != request.user:
#                         try:
#                             SharedFile.objects.update_or_create(
#                                 user=user,
#                                 file=file_instance,
#                                 shared_by=request.user,
#                                 role=role
#                             )
#                         except:
#                             pass
#                         messages.append(f'{file_instance.name} shared with {user.username}')
#                     else:
#                         messages.append(f'Failed to share with {username} (invalid username or sharing with yourself).')
#             else:
#                 file_instance.access_everyone = True
#                 file_instance.save()
#                 messages.append(f'{file_instance.name} shared with everyone')

#             return JsonResponse({'status': 'success', 'messages': messages})
        
#         shared_list = SharedFile.objects.filter(shared_by=request.user, file=file_instance)
#         shared_with_all = file_instance.access_everyone
#         return render(request, 'share_item.html', {'item_type': 'file', 'item_name': file_instance.name, 'item_id': file_instance.id, 'user': request.user, 'sharing_list': shared_list, "access_to_all": shared_with_all, 'item': file_instance})
#     return HttpResponseForbidden('You do not have permission to share this file')

@login_required
def star(request, file_id):
    file = get_object_or_404(File, id=file_id)

    if not (request.user == file.owner or file.access_everyone or file.access_list.contains(request.user) or SharedFile.objects.filter(file=file, user=request.user).exists()):
        return HttpResponseForbidden("You are not permitted to star this file as it is not yours")
    
    if file.owner == request.user:
        if file.starred:
            file.starred = False
        else:
            file.starred = True
    else:
        user = request.user
        if user.starred_files.contains(file):
            user.starred_files.remove(file)
        else:
            user.starred_files.add(file)
        user.save()
    file.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

def get_file_or_404(model, item_id):
    try:
        return model.objects.binned_items().get(id=item_id)
    except model.DoesNotExist:
        try:
            return model.objects.all_with_binned().get(id=item_id)
        except model.DoesNotExist:
            raise Http404("Item does not exist or is binned")

@login_required
def bin(request, file_id):
    file = get_file_or_404(File, item_id=file_id)

    if not (request.user == file.owner or SharedFile.objects.filter(file=file, user=request.user, role=3)):
        if not file.access_list.contains(request.user):
            return HttpResponseForbidden("You do not have the permission to bin this file")
        else:
            file.access_list.remove(request.user)
            file.save()
            if SharedFile.objects.filter(user=request.user, file=file).exists():
                SharedFile.objects.get(user=request.user, file=file).delete()
    if not file.binned:
        file.binned = datetime.now()
        file.save()
    else:
        if file.parent:
            if not file.parent.binned:
                file.binned = None
                file.save()
            else:
                file.parent = None
                file.binned = None
                file.save()
        file.binned = None
        file.save()
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

@login_required
def unzip(request, file_id):
    file = get_object_or_404(File, id=file_id)
    
    if not (file.has_perm(request.user.id) or SharedFile.objects.filter(file=file, user=request.user, role=3)):
        return HttpResponseForbidden("You cannot perform this action")
    if not file.get_extension() == 'zip':
        return HttpResponseForbidden('This is not a zip file so you cannot unzip it.')
    
    file_path = apply_correct_path(file.get_full_path())
    unzip_dir = os.path.join(os.path.splitext(file_path)[0])
    print(unzip_dir)

    try:
        os.makedirs(os.path.dirname(unzip_dir))
    except:
        pass

    with zipfile.ZipFile(file_path, 'r') as zip_ref:
        zip_ref.extractall(unzip_dir)

    root_folder = file.parent
    parent_folder = Folder.objects.create(
        name=file.name.replace('.zip', ''),
        parent=root_folder,
        owner=request.user
    )

    # Iterate through all directories and files in the unzipped content
    for root, dirs, files in os.walk(unzip_dir):
        # Calculate the relative path from the root of the unzipped directory
        relative_path = os.path.relpath(root, unzip_dir)

    #     # Find or create the current parent folder in the database, starting from the root folder
        if relative_path != '.':
            parent_folder, created = Folder.objects.get_or_create(
                name=os.path.basename(root),
                parent=root_folder if relative_path == '.' else parent_folder,
                owner=request.user
            )
        else:
            parent_folder

        # Create subfolders in the database
        for dir_name in dirs:
            Folder.objects.get_or_create(
                name=dir_name,
                parent=parent_folder,
                owner=request.user
            )

        # Create file entries in the database
        for file_name in files:
            file_path = os.path.join(root, file_name)
            relative_file_path = os.path.relpath(file_path, settings.MEDIA_ROOT)
            file_size = os.path.getsize(file_path)  # Get the file size in bytes

            # Create the file entry in the correct folder in the database
            File.objects.create(
                name=file_name,
                file=relative_file_path,
                owner=request.user,
                parent=parent_folder,
                size=file_size  # Set the file size
            )
    if file.parent:
        return redirect('view_folder', folder_id=file.parent.id)
    return redirect('my_files')

def create_zip_file(folder, save_path):
    """
    Create a zip file of the folder and save it to the specified path.
    
    :param folder: The Folder object to be zipped.
    :param save_path: The path where the zip file should be saved.
    :return: The path to the created zip file.
    """
    folder_path = apply_correct_path(folder.get_path())
    zip_filename = os.path.join(save_path, f"{folder.name}.zip")
    
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, os.path.join(folder_path, '..'))
                zip_file.write(file_path, arcname)
    
    return zip_filename

@login_required
def zip_folder(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id)
    if not (folder.owner == request.user or SharedFolder.objects.filter(folder=folder, user=request.user, role=3).exists()):
        messages.error(request, "You cannot perform this action")
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
    save_path = folder.parent.get_path() if folder.parent else os.path.join(settings.MEDIA_ROOT, request.user.username)

    zip_file = create_zip_file(folder, save_path)

    File.objects.create(
        name=f"{folder.name}.zip",
        file=zip_file,
        owner=request.user,
        size=os.path.getsize(zip_file),
        parent=folder.parent
    )

    if folder.parent:
        return redirect('view_folder', folder_id=folder.parent.id)
    return redirect('my_files')


@login_required
def delete_permanently(request, file_id):
    file = get_file_or_404(File, item_id=file_id)
    if file.is_editor(request.user.id):
        file.delete()
        return redirect('binned_view')
    elif file.access_list.contains(request.user) or SharedFile.objects.filter(user=request.user, file=file).exists():
        file.access_list.remove(request.user)
        if SharedFile.objects.filter(user=request.user, file=file).exists():
            SharedFile.objects.get(user=request.user, file=file).delete()
        return redirect('binned_view')
    elif SharedFile.objects.filter(user=request.user, file=file, role=3):
        file.delete()
        return redirect('binned_view')
    else:
        return redirect('binned_view')
    
@login_required
def rename_item(request):
    if request.method == 'POST':
        item_type = request.POST.get('item_type')
        item_id = request.POST.get('item_id')
        new_name = request.POST.get('new_name')
        override = request.POST.get('override')
        print(item_type)
        if item_type == 'file':
            if not override:
                file_instance = get_object_or_404(File, id=item_id)
                print(file_instance.is_editor(request.user.id))
                if not file_instance.is_editor(request.user.id):
                    messages.error(request, "You do not have the rights to rename this item")
                    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
                file_path = os.path.join(settings.MEDIA_ROOT, file_instance.get_full_path())
                new_file_path = os.path.join(os.path.dirname(file_path), new_name)
                try:
                    os.rename(file_path, new_file_path)
                except FileExistsError:
                    messages.error(request, "A folder already exists with this name")
                file_instance.file = new_file_path
                file_instance.name = new_name
                file_instance.save()
            else:
                file_instance = get_object_or_404(File, id=item_id)
                print(file_instance.is_editor(request.user.id))
                if not file_instance.is_editor(request.user.id):
                    messages.error(request, "You do not have rights to rename this item")
                    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
                file_path = os.path.join(settings.MEDIA_ROOT, file_instance.get_full_path())
                new_file_path = os.path.join(os.path.dirname(file_path), new_name)
                if os.path.exists(new_file_path):
                    os.remove(new_file_path)
                os.rename(file_path, new_file_path)
                file_instance.file = new_file_path
                if File.objects.filter(parent=file_instance.parent, name=new_name).exists():
                    to_be_del = File.objects.get(parent=file_instance.parent, name=new_name)
                    to_be_del.delete()
                file_instance.name = new_name
                file_instance.save()
        if item_type == 'folder':
            if not override:
                try:
                    folder_instance = get_object_or_404(Folder, id=item_id)
                    if not (folder_instance.is_editor(request.user.id)):
                        messages.error(request, "You do not have the rights to rename this item")
                        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
                    folder_path = os.path.join(settings.MEDIA_ROOT, folder_instance.get_path())
                    new_folder_path = os.path.join(os.path.dirname(folder_path), new_name)
                    os.rename(folder_path, new_folder_path)
                    folder_instance.name = new_name
                    folder_instance.save()
                except FileExistsError:
                    messages.error(request, "The folder you are trying to rename to already exists or is in bin")
                    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
            else:
                folder_instance = get_object_or_404(Folder, id=item_id)
                if not folder_instance.is_editor(request.user.id):
                    messages.error(request, "You do not have the rights to rename this item")
                    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
                folder_path = apply_correct_path(folder_instance.get_path())
                new_folder_path = os.path.join(os.path.dirname(folder_path), new_name)
                if os.path.exists(new_folder_path):
                    shutil.rmtree(new_folder_path)
                os.rename(folder_path, new_folder_path)
                if Folder.objects.filter(parent=folder_instance.parent, name=new_name).exists():
                    to_be_del = Folder.objects.get(parent=folder_instance, name=new_name)
                    to_be_del.delete()
                folder_instance.name = new_name
                folder_instance.save()

        messages.success(request, 'Item renamed successfully')
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

@login_required
def copy_shared_file(request, file_id):
    file_instance = get_object_or_404(File, id=file_id)

    if not (file_instance.access_list.contains(request.user) or file_instance.access_everyone):
        return HttpResponseForbidden("You do not have access to this file")
    print(file_instance.file)
    File.objects.create(
        name=file_instance.name,
        owner=request.user,
        file=file_instance.file,
        parent=None,
        size=file_instance.size
    )
    messages.success(request, "File has been successfully copied to Your Files")
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

def apply_correct_path(path):
    return os.path.join(settings.MEDIA_ROOT, path)

@login_required
def move_item(request, destination_item_id, item_id):
    destination = None
    if destination_item_id != 'home':
        destination = get_object_or_404(Folder, id=destination_item_id)
        if not (destination.owner == request.owner or SharedFolder.objects.filter(user=request.user, folder=destination, role=3).exists()):
            return JsonResponse({"status": "Error", "message": "You do not have the permission to move to this destination"})
    print(item_id, destination_item_id)
    message = "There was an error"
    status = "Error"
    try:
        file = File.objects.get(id=item_id, owner=request.user)
        file_name, ext = os.path.splitext(file.name)
        destination_path = destination.get_path() + f'\\{file_name}{ext}' if destination_item_id != 'home' else request.user.username + f'\\{file.name}'
        counter = 1
        while os.path.exists(apply_correct_path(destination_path)): 
            destination_path = destination.get_path() + f'\\{file_name} ({counter}){ext}' if destination_item_id != 'home' else request.user.username + f'\\{file_name} ({counter}){ext}'
            counter += 1
        print(destination_path)
        print(apply_correct_path(destination_path))
        if file.parent == destination or (destination == "home" and not file.parent):
            message = "File has already been moved to location"
        else:
            os.rename(apply_correct_path(file.get_full_path()), apply_correct_path(destination_path))
            file.name = os.path.basename(destination_path)
            file.file = destination_path
            file.parent = destination
            file.save()
            message = "File has been successfully moved to new location"
            status = "success"
    except File.DoesNotExist:
        try:
            folder = Folder.objects.get(id=item_id, owner=request.user)
            if destination == folder:
                return JsonResponse({"status": "success", "message": "You can't move this folder into the same folder"})
            destination_path = destination.get_path() + f'\\{folder.name}' if destination_item_id != 'home' else request.user.username + f"\\{folder.name}"
            counter = 1
            while os.path.exists(apply_correct_path(destination_path)):
                destination_path = destination.get_path() + f'\\{folder.name} ({counter})' if destination_item_id != 'home' else request.user.username + f"\\{folder.name} ({counter})"
                counter += 1
            os.rename(apply_correct_path(folder.get_path()), apply_correct_path(destination_path))
            folder.parent = destination
            folder.save()
            move_all_subs(folder)
            message = "Folder has been successfully moved to new location"
            status = "success"
        except Folder.DoesNotExist: 
            pass
    return JsonResponse({"status": status, "message": message})

def move_all_subs(folder):
    for file in folder.subfiles.all():
        file.file = os.path.join(folder.get_path(), file.name)
        file.save()
    for folder in folder.subfolders.all():
        if folder.subfiles.all():
            move_all_subs(folder)

@login_required
def change_role(request):
    if request.method == 'POST':
        sharing_id = request.POST.get('sharing_id')
        try:
            sharedfolder = SharedFolder.objects.get(id=sharing_id, shared_by=request.user)
            sharedfolder.role = request.POST.get('new_role', sharedfolder.role)
            sharedfolder.save()
            return JsonResponse({"status": 'success', "message": 'The role of this user has been successfully changed'})
        except SharedFolder.DoesNotExist:
            try:
                sharedfile = SharedFile.objects.get(id=sharing_id, shared_by=request.user)
                sharedfile.role = request.POST.get('new_role', sharedfile.role)
                sharedfile.save()
                return JsonResponse({"status": 'success', "message": 'The role of this user has been successfully changed'})
            except SharedFile.DoesNotExist:
                return JsonResponse({"status": 'success', "message": 'There was an error.'})
    return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

@login_required
def remove_access(request):
    if request.method == 'POST':
        sharing_id = request.POST.get('sharing_id')
        try: 
            sharing = SharedFile.objects.get(id=sharing_id, shared_by=request.user)
            file = get_object_or_404(File, id=sharing.file.id)
            file.access_list.remove(sharing.user)
            file.save()
            sharing.delete()
            return JsonResponse({'status': 'success', 'message': 'This user has been successfully denied access to this file'})
        except Exception:
            try:
                sharing = SharedFolder.objects.get(id=sharing_id, shared_by=request.user)
                folder = get_object_or_404(Folder, id=sharing.folder.id)
                folder.access_list.remove(sharing.user)
                folder.save()
                sharing.delete()
                return JsonResponse({'status': 'success', 'message': 'This user has been denied access to this folder successfully'})
            except Exception:
                return JsonResponse({'status': 'success', 'message': 'There was an error'})
            
