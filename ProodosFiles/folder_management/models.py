import os
import shutil
import uuid
from django.conf import settings
from django.db import models
from django.db.models import QuerySet
from django.contrib.auth import get_user_model
from django.apps import apps
from datetime import datetime

from django.shortcuts import get_object_or_404

CustomUser = get_user_model()

class FileFolderQuerySet(QuerySet):
    def not_binned(self):
        return self.filter(binned__isnull=True)

    def binned(self):
        return self.filter(binned__isnull=False)
    
class FileFolderManager(models.Manager):
    def get_queryset(self):
        return FileFolderQuerySet(self.model, using=self._db).not_binned()

    def all_with_binned(self):
        return FileFolderQuerySet(self.model, using=self._db)

    def binned_items(self):
        return self.all_with_binned().binned()

class Folder(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey('user_management.CustomUser', on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    description = models.CharField(max_length=1000, blank=True, null=True)
    parent = models.ForeignKey('self', null=True, blank=True, related_name='subfolders', on_delete=models.CASCADE)
    access_list = models.ManyToManyField('user_management.CustomUser', related_name='shared_with_me_folders', blank=True)
    access_everyone = models.BooleanField(default=False)
    access_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    starred = models.BooleanField(default=False)
    binned = models.DateTimeField(null=True, blank=True)

    objects = FileFolderManager()

    def get_path(self):
        if self.parent:
            return os.path.join(self.parent.get_path(), str(self.id))
        return os.path.join(str(self.owner.id), str(self.id))

    def save(self, *args, **kwargs):
        # try:
        #     if not Folder.objects.get(owner=self.owner, name=self.name, parent=self.parent).id == self.id:
        #         counter = 1
        #         unique_name = self.name
        #         directory = self.parent.get_path() if self.parent else os.path.join(settings.MEDIA_ROOT, self.owner.username)
                
        #         while os.path.exists(os.path.join(directory, unique_name)):
        #             base = self.name
        #             unique_name = f"{base} ({counter})"
        #             counter += 1

        #         self.name = unique_name
        # except:
        #     pass
        if self.parent:
            self.access_everyone = self.parent.access_everyone
            if self.parent.binned:
                self.binned = self.parent.binned
        super(Folder, self).save(*args, **kwargs)
        # Create the folder in the filesystem
        folder_path = os.path.join(settings.MEDIA_ROOT, self.get_path())
        if not os.path.exists(folder_path):
            os.makedirs(folder_path)
        if self.parent:
            if SharedFolder.objects.filter(folder=self.parent).exists():
                for sharing in SharedFolder.objects.filter(folder=self.parent).all():
                    SharedFolder.objects.get_or_create(folder=self, user=sharing.user, role=sharing.role, shared_by=sharing.shared_by, visible=False)
            for usern in self.parent.access_list.all():
                self.access_list.add(usern)
            # Also share this folder with its subfolders and files if they exist
            for subfolder in self.subfolders.all():
                for usern in self.access_list.all():
                    subfolder.access_list.add(usern)
                subfolder.save()
            for file in self.subfiles.all():
                for usern in self.access_list.all():
                    file.access_list.add(usern)
                file.save()

    def delete(self, *args, **kwargs):
        # Delete all files and subfolders within this folder
        for subfolder in self.subfolders.all():
            subfolder.delete()
        for file in self.subfiles.all():
            file.delete()

        # Remove the folder from the physical storage
        folder_path = os.path.join(settings.MEDIA_ROOT, self.get_path())
        if os.path.exists(folder_path):
            shutil.rmtree(folder_path)

        # Finally, delete the folder from the database
        super().delete(*args, **kwargs)
    
    def has_perm(self, user_id):
        user = get_object_or_404(CustomUser, id=user_id)
        if self.access_everyone or self.access_list.contains(user) or SharedFolder.objects.filter(user=user, folder=self).exists():
            return True
        return False
    
    def is_editor(self, user_id):
        user = get_object_or_404(CustomUser, id=user_id)
        if self.owner == user or SharedFolder.objects.filter(user=user, folder=self, role=3):
            return True
        return False
    
    def deny_access(self, user_id):
        user = get_object_or_404(CustomUser, id=user_id)
        if self.access_list.contains(user):
            self.access_list.remove(user)
            self.save()
        if SharedFolder.objects.filter(user=user, folder=self).exists():
            to_be_del = SharedFolder.objects.get(user=user, folder=self)
            to_be_del.delete()


    def __str__(self):
        return self.name

class SharedFolder(models.Model):
    roleChoices = (
        (1, "Viewer"),
        (2, "Commentor"),
        (3, "Editor"),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('user_management.CustomUser', on_delete=models.CASCADE)
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
    shared_by = models.ForeignKey('user_management.CustomUser', related_name='folder_shared_by', on_delete=models.CASCADE)
    shared_at = models.DateTimeField(auto_now_add=True)
    role = models.CharField(choices=roleChoices, max_length=255, null=False, default=1)
    visible = models.BooleanField(default=True)
    class Meta:
        unique_together = ('user', 'folder')

    def __str__(self):
        return f'{self.user.username} shared {self.folder} by {self.shared_by.username}'