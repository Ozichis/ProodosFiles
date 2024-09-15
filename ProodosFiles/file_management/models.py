import os
import shutil
import uuid
from django.conf import settings
from django.db import models
from django.apps import apps
from django.dispatch import receiver
from django.shortcuts import get_object_or_404
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db.models.signals import post_delete, post_save
from folder_management.models import Folder, FileFolderManager, SharedFolder
from cryptography.fernet import Fernet
# from user_management.models import CustomUser

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from io import BytesIO


class FileEncryption:
    def __init__(self, key):
        self.key = key

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC)
        iv = cipher.iv  # Initialization vector
        encrypted_data = cipher.encrypt(pad(data, AES.block_size))
        return iv + encrypted_data  # Save IV + encrypted data

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:AES.block_size]  # Extract the IV
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
        return decrypted_data



# Encrypting data

CustomUser = get_user_model()

def apply_correct_path(path):
    return os.path.join(settings.MEDIA_ROOT, path)

# Create your models here.
class File(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    file = models.FileField(upload_to='temp/', blank=True)
    name = models.CharField(max_length=255)
    size = models.PositiveBigIntegerField()
    description = models.CharField(max_length=1000, blank=True)
    parent = models.ForeignKey(Folder, on_delete=models.CASCADE, related_name='subfiles', null=True, blank=True)
    upload_date = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(auto_now=True)
    access_list = models.ManyToManyField(CustomUser, related_name='shared_with_me_files', blank=True)
    access_everyone = models.BooleanField(default=False)
    access_count = models.IntegerField(default=0)
    starred = models.BooleanField(default=False)
    binned = models.DateTimeField(null=True, blank=True)
    thumbnail = models.ImageField(default="thumbnail.png", upload_to="temp/")
    objects = FileFolderManager()

    def get_full_path(self):
        if self.parent:
            return os.path.join(self.parent.get_path(), str(self.id) + "." + self.get_extension())
        return os.path.join(str(self.owner.id), str(self.id) + "." + self.get_extension())
    
    def get_extension(self):
        var = self.name.split('.')
        if len(var) > 1:
            return var[-1]
        return None
    


    def generate_thumbnail(self):
        from thumbnail import generate_thumbnail

        options = {
    	    'trim': False,
	        'height': 300,
	        'width': 300,
	        'quality': 85,
	        'type': 'thumbnail'
        }
        encrytor = Fernet(settings.FILE_ENCRYPTION_KEY)
        new_thumbnail_name = f"{self.id}-0893.png"
        thumbnail_path = os.path.join(os.path.dirname(self.get_full_path()), new_thumbnail_name)
        print(thumbnail_path, "didd")
        self.thumbnail.name = new_thumbnail_name
        # print(thumbnail_path, "i did it")
        generate_thumbnail(self.file, apply_correct_path(thumbnail_path), options)
        with open(apply_correct_path(thumbnail_path), 'rb') as data:
            infor = data.read()
        with open(apply_correct_path(thumbnail_path), 'wb') as file:
            file.write(encrytor.encrypt(infor))
        self.thumbnail = thumbnail_path

    def save(self, override=False, *args, **kwargs):
        if self.owner.used_space + self.size > self.owner.quota:
            raise ValidationError("You have exceeded your quota")
        if override:
            if File.objects.filter(owner=self.owner, parent=self.parent, name=self.name).exists():
                file = File.objects.get(owner=self.owner, parent=self.parent, name=self.name)
                file.delete()
        try:
            if not File.objects.get(owner=self.owner, name=self.name, parent=self.parent).id == self.id:
                counter = 1
                unique_name = self.name
                print(unique_name)
                directory = self.parent.get_path() if self.parent else os.path.join(settings.MEDIA_ROOT, self.owner.username)
                
                while File.objects.filter(owner=self.owner, name=self.name, parent=self.parent).exists():
                    base, extension = os.path.splitext(self.name)
                    unique_name = f"{base} ({counter}){extension}"
                    counter += 1

                self.name = unique_name
        except:
            pass
        try:
            if not File.objects.get(parent=self.parent, name=self.name, owner=self.owner).id == self.id:
                self.generate_thumbnail()
                shutil.copyfile(apply_correct_path(os.path.join("temp", self.thumbnail.name)), apply_correct_path(os.path.join(os.path.dirname(file_path), self.thumbnail.name)))
                super(File, self).save(update_fields=['thumbnail'])
        except:
            pass
        super(File, self).save(*args, **kwargs)
        
        if self.parent:
            self.access_everyone = self.parent.access_everyone
            if SharedFolder.objects.filter(folder=self.parent).exists():
                for sharing in SharedFolder.objects.filter(folder=self.parent).all():
                    print(self)
                    try:
                        SharedFile.objects.get_or_create(file=self, user=sharing.user, role=sharing.role, shared_by=sharing.shared_by, visible=False)
                    except:
                        pass
                    print('did')
            if self.parent.binned:
                self.binned = self.parent.binned

        # Move the file to the correct folder path
        file_path = os.path.join(settings.MEDIA_ROOT, self.get_full_path())
        if self.parent:
            for usern in self.parent.access_list.all():
                self.access_list.add(usern)
            
            self.access_everyone = self.parent.access_everyone
        if not os.path.exists(os.path.dirname(file_path)):
            os.makedirs(os.path.dirname(file_path))
        print(self.file.path)
        
        if not os.path.exists(file_path):
            shutil.copyfile(self.file.path, file_path)
            self.file.name = self.name  # Update the file path relative to MEDIA_ROOT
            self.file = self.get_full_path()
            key = settings.FILE_ENCRYPTION_KEY
            encrytor = Fernet(key)
            with open(file_path, 'rb') as file:
                to_be_enc = file.read()
            with open(file_path, 'wb') as file:
                file.write(encrytor.encrypt(to_be_enc))
            super(File, self).save(update_fields=['file'])
        temp_file_path = os.path.join(settings.MEDIA_ROOT, f"temp/{self.id}.{self.get_extension()}")
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)

    def delete(self, *args, **kwargs):
        # Remove the file from the physical storage
        file_path = os.path.join(settings.MEDIA_ROOT, self.get_full_path())
        print(file_path)
        if os.path.exists(file_path):
            os.remove(file_path)

        # Finally, delete the file from the database
        super().delete(*args, **kwargs)
    
    def has_perm(self, user_id):
        user = get_object_or_404(CustomUser, id=user_id)
        if self.owner == user or self.access_everyone or self.access_list.contains(user) or SharedFile.objects.filter(user=user, file=self).exists():
            return True
        return False

    def is_editor(self, user_id):
        user = get_object_or_404(CustomUser, id=user_id)
        if self.owner == user or SharedFile.objects.filter(user=user, file=self, role=3).exists():
            return True
        return False
    
    def deny_access(self, user_id):
        user = get_object_or_404(CustomUser, id=user_id)
        if self.access_list.contains(user):
            self.access_list.remove(user)
            self.save()
        if SharedFile.objects.filter(user=user, file=self).exists():
            to_be_del = SharedFile.objects.get(user=user, file=self)
            to_be_del.delete()

    def __str__(self):
        return self.name
    

class SharedFile(models.Model):
    roleChoices = (
        (1, "Viewer"),
        (2, "Editor"),
        (3, "Commentor"),
    )
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    file = models.ForeignKey(File, null=True, blank=True, on_delete=models.CASCADE)
    shared_by = models.ForeignKey(CustomUser, related_name='file_shared_by', on_delete=models.CASCADE)
    shared_at = models.DateTimeField(auto_now_add=True)
    role = models.CharField(choices=roleChoices, max_length=255, default=1)
    visible = models.BooleanField(default=True)

    class Meta:
        unique_together = ('user', 'file')

    def __str__(self):
        return f'{self.user.username} shared {self.file} by {self.shared_by.username}'
    
@receiver(post_save, sender=File)
def update_quota_on_save(sender, instance, created, **kwargs):
    if created:
        # New file uploaded, add its size to the used space
        instance.owner.used_space += instance.size
    else:
        # Existing file updated, handle changes in size if needed
        old_instance = File.objects.all_with_binned().get(id=instance.id)
        size_difference = instance.size - old_instance.size
        instance.owner.used_space += size_difference
    # encryption = FileEncryption(key=settings.FILE_ENCRYPTION_KEY)
    instance.owner.save()

@receiver(post_delete, sender=File)
def update_quota_on_delete(sender, instance, **kwargs):
    # File deleted, subtract its size from the used space
    instance.owner.used_space -= instance.size
    if instance.owner.used_space < 0:
        instance.owner.used_space = 0
    instance.owner.save()