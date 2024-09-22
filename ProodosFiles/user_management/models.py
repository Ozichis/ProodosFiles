import os
import shutil
import uuid
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.apps import apps
from django.dispatch import receiver
from django.db.models.signals import post_save, post_delete

# from file_management.models import File
# from folder_management.models import Folder

class CustomUserManager(BaseUserManager):
    def create_user(self, username, email, password=None, **extra_fields):
        if not email:
            raise ValueError('The Email field must be set')
        if not username:
            raise ValueError("The Username field must be set")
        email = self.normalize_email(email)
        user = self.model(username=username.strip(), email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self.create_user(username, email, password, **extra_fields)

class CustomUser(AbstractUser):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    starred_files = models.ManyToManyField('file_management.File', blank=True)
    starred_folders = models.ManyToManyField('folder_management.Folder', blank=True)
    username = models.CharField(
        max_length=150,
        unique=True,
        help_text='Required. Letters, digits, and spaces only. Max 150 characters',
        validators=[],
        error_messages={
            'unique': "A user with that username already exists.",
        },
    )
    full_name = models.CharField(
        max_length=255,
        help_text='Required field. ',
        validators=[],
    )
    email = models.EmailField(
        max_length=254,
        unique=True,
        help_text='Email is required.',
        validators=[],
        error_messages={
            'unique': 'This email has already been registered',
        },
    )

    quota = models.BigIntegerField(default=15 * 1024 * 1024 * 1024)
    used_space = models.BigIntegerField(default=0)


    objects = CustomUserManager()

    def __str__(self):
        return self.username
    

class FriendShip(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    friend = models.ForeignKey(CustomUser, related_name="friends", on_delete=models.CASCADE)
    
    def __str__(self):
        return f"{self.user} is friends with {self.friend}"
    
class FriendRequest(models.Model):
    id = models.UUIDField(default=uuid.uuid4, primary_key=True, editable=False)
    from_user = models.ForeignKey(CustomUser, related_name='sent_requests', on_delete=models.CASCADE)
    to_user = models.ForeignKey(CustomUser, related_name='received_requests', on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now=True)

    def accept(self):
        FriendShip.objects.create(user=self.to_user, friend=self.from_user)
        FriendShip.objects.create(user=self.from_user, friend=self.to_user)
        self.delete()

    def decline(self):
        self.delete()

    def __str__(self):
        return f"{self.from_user} wants to be friends with {self.to_user}"

@receiver(post_save, sender=CustomUser)
def create_user_directory(sender, instance, created, **kwargs):
    if created:
        user_directory = os.path.join(settings.MEDIA_ROOT, str(instance.id))
        os.makedirs(user_directory)

@receiver(post_delete, sender=CustomUser)
def delete_user_directory(sender, instance, created=True, **kwargs):
    user_directory = os.path.join(settings.MEDIA_ROOT, str(instance.id))
    if os.path.exists(user_directory):
        shutil.rmtree(user_directory)