from datetime import datetime
import os
from django.http import HttpResponseRedirect
from django.shortcuts import redirect, render
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from file_management.models import File, SharedFile
from folder_management.models import Folder, SharedFolder

@login_required
def home(request):
    # Fetch suggested folders
    recent_folders = Folder.objects.filter(owner=request.user).order_by('-id')[:4]
    frequent_folders = Folder.objects.filter(owner=request.user).order_by('-access_count')[:4]
    shared_folders = Folder.objects.filter(access_list=request.user)[:4]

    # Fetch suggested files
    recent_files = File.objects.filter(owner=request.user).order_by('-last_accessed')[:4]
    frequent_files = File.objects.filter(owner=request.user).order_by('-access_count')[:4]
    shared_files = File.objects.filter(access_list=request.user)[:4]

    temp_suggested_folders = [
        {'folders': recent_folders, 'reason': 'Recently Accessed'},
        {'folders': frequent_folders, 'reason': 'Frequently Accessed'},
        {'folders': shared_folders, 'reason': 'Shared with You'},
    ]

    suggested_folders = [
        {'folders': [], 'reason': 'Recently Accessed'},
        {'folders': [], 'reason': 'Frequently Accessed'},
        {'folders': [], 'reason': 'Shared with You'},
    ]

    seen_folder_ids = set()
    
    for i in range(0, 3):
        for folder in temp_suggested_folders[i]['folders']:
            if folder.id not in seen_folder_ids:
                suggested_folders[i]['folders'].append(folder)
                seen_folder_ids.add(folder.id)



    temp_suggested_files = [
        {'files': recent_files, 'reason': 'Recently Accessed'},
        {'files': frequent_files, 'reason': 'Frequently Accessed'},
        {'files': shared_files, 'reason': 'Shared with You'},
    ]

    suggested_files = [
        {'files': [], 'reason': 'Recently Accessed'},
        {'files': [], 'reason': 'Frequently Accessed'},
        {'files': [], 'reason': 'Shared with You'},
    ]

    seen_file_ids = set()
    
    for i in range(0, 3):
        for file in temp_suggested_files[i]['files']:
            if file.id not in seen_file_ids:
                suggested_files[i]['files'].append(file)
                seen_file_ids.add(file.id)

    print(suggested_files)

    no_files = False
    no_folders = False

    if not (suggested_files[0]['files'] or suggested_files[1]['files'] or suggested_files[2]['files']):
        no_files = True
    if not (suggested_folders[0]['folders'] or suggested_folders[1]['folders'] or suggested_folders[2]['folders']):
        no_folders = True

    context = {
        'suggested_folders': suggested_folders,
        'suggested_files': suggested_files,
        'user': request.user,
        'no_files': no_files,
        'no_folders': no_folders
    }
    return render(request, 'home.html', context)

@login_required
def all_files(request):
    folders = Folder.objects.filter(owner=request.user, parent=None)
    files = File.objects.filter(owner=request.user, parent=None)
    all_folders = Folder.objects.filter(owner=request.user)
    
    if request.method == "POST":
        folder_name = request.POST.get('folder_name')
        if Folder.objects.filter(name=str(folder_name), parent=None, owner=request.user).first():
            folder = Folder.objects.get(name=str(folder_name), parent=None, owner=request.user)
            return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
        new_folder = Folder.objects.create(name=str(folder_name), owner=request.user)
        new_folder.save()
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))

    return render(request, 'files_folders.html', {'folders': folders, 'files': files, 'all_folders': all_folders})

@login_required
def starred_items(request):
    from itertools import chain
    from operator import attrgetter
    folders = Folder.objects.filter(owner=request.user, starred=True)
    my_starred_folders = request.user.starred_folders.all()
    files = File.objects.filter(owner=request.user, starred=True)
    my_starred_files = request.user.starred_files.all()

    folders = sorted(chain(folders, my_starred_folders), key=lambda instance: instance.created_at)
    files = sorted(chain(files, my_starred_files), key=lambda instance: instance.upload_date)

    for file in range(0, len(files)):
        if files[file].has_perm(request.user.id):
            pass
        else:
            request.user.starred_files.remove(files[file])
            request.user.save()
            del files[file]

    for folder in range(0, len(folders)):
        if folders[folder].has_perm(request.user.id):
            pass
        else:
            request.user.starred_folders.remove(folders[folder])
            request.user.save()
            del folders[folder]
        
    return render(request, 'files_folders.html', {'folders': folders, 'files': files, 'starred': True})

@login_required
def view_shared_items(request):
    # Fetch all shared items (both files and folders) shared with the logged-in user
    shared_folders = SharedFolder.objects.filter(user=request.user, visible=True)
    shared_files = SharedFile.objects.filter(user=request.user, visible=True)

    # Separate files and folders
    shared_files = [item.file for item in shared_files if item.file is not None]
    shared_folders = [item.folder for item in shared_folders if item.folder is not None]

    context = {
        'shared_files': shared_files,
        'shared_folders': shared_folders,
    }

    return render(request, 'view_shared_items.html', context)

@login_required
def binned_view(request):
    binned_files = File.objects.binned_items().filter(owner=request.user)
    binned_folders = Folder.objects.binned_items().filter(owner=request.user)

    now = timezone.now()
    cutoff_date = now - timezone.timedelta(days=30)

    files_to_delete = binned_files.filter(binned__lte=cutoff_date)
    folders_to_delete = binned_folders.filter(binned__lte=cutoff_date)   

    for file in files_to_delete:
        file.delete()
        if os.path.exists(file.get_full_path()):
            os.remove(file.get_full_path())

    for folder in folders_to_delete:
        folder.delete()
        if os.path.exists(folder.get_path()):
            os.remove(folder.get_path())

            
    context = {
        'binned_files': binned_files,
        'binned_folders': binned_folders
    }
    return render(request, 'bin_view.html', context)

@login_required
def go_back(request):
    last_three_urls = request.session.get('last_three_urls', [])
    print(last_three_urls)
    
    if len(last_three_urls) >= 3:
        # Redirect to the second last URL
        return redirect(last_three_urls[-3])
    else:
        # Fallback if there are not enough URLs in the history
        return HttpResponseRedirect(request.META.get('HTTP_REFERER', '/'))
    
def error_404(request, exception, error_note=None):
    return render(request, "404.html", context={"error": exception, "error_note": error_note}, status=404)

def error_403(request, exception):
    return render(request, "403.html", context={"error": exception}, status=403)