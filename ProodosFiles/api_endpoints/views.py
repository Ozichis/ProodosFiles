import base64
from datetime import datetime, timedelta
import hashlib
import os
import re
import shutil
import chardet
from django.conf import settings
from django.urls import reverse
from rest_framework import serializers, generics, views, status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.parsers import MultiPartParser, JSONParser, BaseParser

from django.http import FileResponse, Http404, HttpResponseForbidden, JsonResponse
from django.utils.http import urlencode
from django.urls import reverse
from django.shortcuts import get_object_or_404, redirect, render
from django.core.validators import RegexValidator
from django.contrib.auth.decorators import login_required
from django.contrib.auth.backends import ModelBackend
from cryptography.fernet import Fernet

from django.core.files.storage import default_storage

from file_management.models import File, SharedFile, apply_correct_path
from folder_management.models import Folder, SharedFolder
from user_management.forms import RegistrationForm
from user_management.models import CustomUser

from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator, PasswordResetTokenGenerator

from django.core.signing import TimestampSigner, BadSignature, SignatureExpired
from django.core.mail import send_mail

from django.template.loader import render_to_string

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.html import strip_tags
from django.utils.encoding import force_bytes, force_str

from user_management.token import account_activation_token

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from drf_spectacular.utils import extend_schema, OpenApiParameter, extend_schema_field, OpenApiExample
from drf_spectacular.types import OpenApiTypes



def createBasicResponse(status=200, responseText='', data=''):
    return {'status': status, 'responseText': responseText, 'data': data}

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    
    # Add the URL field with the validator
    url = serializers.URLField(
        required=True
    )
    
    
    class Meta:
        model = CustomUser
        fields = ['username', 'full_name', 'email', 'password', 'url']

    @extend_schema_field(OpenApiTypes.STR)
    def get_url_field_schema(self):
        return OpenApiTypes.STR
    
    def validate(self, attrs):
        # Validate username uniqueness
        username = attrs.get('username')
        if CustomUser.objects.filter(username=username).exists():
            raise serializers.ValidationError("This username is already taken.")
        
        # Validate email uniqueness
        email = attrs.get('email')
        if CustomUser.objects.filter(email=email).exists():
            raise serializers.ValidationError("This email address is already registered.")
        
        return attrs

    def create(self, validated_data):
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            full_name=validated_data['full_name'],
            is_active=False  # Prevent login until email is verified
        )
        user.set_password(validated_data['password'])
        user.quota = 10 * 1024 * 1024
        user.save()
        self.send_verification(self.context['request'], user, validated_data['url'])
        return user

    def send_verification(self, request, user, url):
        current_site = get_current_site(request)
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        print(user.pk, "pk")
        print(token)
        print(uidb64)
        url_tail = str({"token": f"{token}", "u_id": f"{uidb64}"}).encode("ascii")
        mail_subject = 'Activation link'  
        message = render_to_string('acc_active_email.html', {  
            'user': user,  
            'url': url,  
            'uid':urlsafe_base64_encode(url_tail),   
        })
        to_email = user.email
        print(to_email)
        plain_message = strip_tags(message)
        send_mail(mail_subject, plain_message, "verify@codedextersacademy.com", [to_email], html_message=message)
        print("sent")

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    @extend_schema(
            description="API for registering user details. URL field is required for this to work."
    )
    def create(self, request, *args, **kwargs):
        # Call the serializer to create the user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        print(serializer.validated_data)
        # return serializer.validated_data

        # Send success response after registration
        return Response(
            {
                "data": "",
                "responseText": "Registration successful. Please check your email to verify your account.",
                "status": 201
                # "user": {
                #     "username": user.username,
                #     "email": user.email
                # }
            }, 
            status=status.HTTP_201_CREATED
        )
    
    def handle_exception(self, exc):
        # Handle exceptions raised by the serializer
        if isinstance(exc, serializers.ValidationError):
            # Format validation errors as JSON
            print(exc.detail)
            result = []
            for key in exc.detail:
                for errors in exc.detail[key]:
                    result.append(errors)

            return Response({
                "status": 400,
                "responseText": result
            }, status=status.HTTP_400_BAD_REQUEST)

        # For other exceptions, fallback to default behavior
        return super().handle_exception(exc)

User = get_user_model()

class ResendSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResendVerificationEmailView(views.APIView):
    serializer_class = ResendSerializer
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    @extend_schema(
        description="Resends a verification email if former link has expired",
        summary="",
        responses={
            200: OpenApiExample(
                "Success",
                value={
                    "responseText": "Email sent if user exists"
                }
            )
        }
    )
    def post(self, request):
        email = request.data.get('email')
        
        try:
            # Get the user by email
            user = CustomUser.objects.get(email=email)
            
            # Ensure the user is not already active
            if user.is_active:
                return Response({'responseText': 'This account is already verified.'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Resend the verification email
            RegisterSerializer().send_verification(request, user, request.data.get('url'))
            return Response({'responseText': 'Email sent if it exists on our server.'}, status=status.HTTP_200_OK)
        
        except CustomUser.DoesNotExist:
            return Response({'responseText': 'Email sent if it exists on our server.'}, status=status.HTTP_400_BAD_REQUEST)
    
    def send_verification(self, request, user, url):
        current_site = get_current_site(request)
        token = default_token_generator.make_token(user)
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        print(user.pk, "pk")
        print(token)
        print(uidb64)
        url_tail = str({"token": f"{token}", "u_id": f"{uidb64}"}).encode("ascii")
        mail_subject = 'Activation link'  
        message = render_to_string('acc_active_email.html', {  
            'user': user,  
            'url': url,  
            'uid':urlsafe_base64_encode(url_tail),   
        })
        to_email = user.email
        print(to_email)
        plain_message = strip_tags(message)
        send_mail(mail_subject, plain_message, "verify@codedextersacademy.com", [to_email], html_message=message)
        print("sent")


class VerifyEmailSerializer(serializers.Serializer):
    uidb64 = serializers.CharField()
    token = serializers.CharField()

    def validate(self, data):
        uidb64 = data.get('uidb64')
        token = data.get('token')
        print(uidb64)
        print(token)
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = CustomUser.objects.get(pk=uid)
        except(TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            raise serializers.ValidationError("Invalid user or UID")
        print(default_token_generator.check_token(user, token))
        if default_token_generator.check_token(user, token):
            return user
        raise serializers.ValidationError("Invalid token or expired")
        
class VerifyEmailView(views.APIView):
    serializer_class = VerifyEmailSerializer
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]
    
    @extend_schema(
        description="API for verifying email. uidb64 and token are to be passed as payload."
    )
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        print(request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            user.is_active = True
            user.quota = 15 * 1024 * 1024 * 1024
            user.save()
            return Response({'responseText': 'Email verified successfully', 'status': 200}, status=status.HTTP_200_OK)
        return Response({'responseText': 'Invalid or expired verification link', 'status': 400}, status=status.HTTP_400_BAD_REQUEST)


@extend_schema_field(serializers.CharField)
def get_url_schema():
    return OpenApiExample(
        "Example URL",
        value="https://www.example.com",
        description="Please provide a valid URL."
    )
    

def authenticates(email=None, password=None, **kwargs):
    UserModel = get_user_model()
    try:
        user = UserModel.objects.get(email=email)
    except UserModel.DoesNotExist:
        return None
    else:
        if user.check_password(password):
            return user
    return None

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('email')
        password = data.get('password')
        user = authenticates(email=username, password=password)
        print(user)
        if user:
            return user
        raise serializers.ValidationError("Invalid credentials or account not activated.")

class PlainTextParser(BaseParser):
    """
    Plain text parser for handling text/plain requests.
    """
    media_type = 'text/plain'

    def parse(self, stream, media_type=None, parser_context=None):
        """
        Simply return a string from the incoming request.
        """
        return stream.read().decode('utf-8')

class LoginView(APIView):
    serializer_class = LoginSerializer
    parser_classes = [PlainTextParser, JSONParser]  # Specify the serializer class
    
    @extend_schema(
        description="API for login. Sends back a token to be saved on browser."
    )
    def post(self, request, *args, **kwargs):
        # request['Referrer-Policy'] = 'no-referrer'
        serializer = self.serializer_class(data=eval(str(request.data)))
        print(eval(str(request.data)))
        if serializer.is_valid():
            user = serializer.validated_data
            token, created = Token.objects.get_or_create(user=user)
            response = {'token': token.key, 'username': user.username, 'full_name': user.full_name, "email": user.email}
            print(response)
            return Response(response, status=200)
        print('bad')
        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        print(response)
        return Response(response, status=400)
    
class FileUploadSerializer(serializers.Serializer):
    files = serializers.ListField(
        child=serializers.FileField(),
        allow_empty=False
    )
    folder_id = serializers.UUIDField(required=False)
    override = serializers.BooleanField(default=False)

    def validate(self, data):
        if data.get('folder_id'):
            if Folder.objects.filter(id=data.get('folder_id')).exists():
                return data
            return serializers.ValidationError("Folder does not exist")
        return data
    # class Meta:
    #     model = File
    #     fields = ['id', 'name', 'file', 'size']
    #     read_only_fields = ['id', 'name', 'size']

    # def create(self, validated_data):
    #     request = self.context.get('request')
    #     folder = self.context.get('folder')
    #     file_instance = File(
    #         name=validated_data['file'].name,
    #         owner=request.user,
    #         parent=folder,
    #         file=validated_data['file'],
    #         size=validated_data['file'].size
    #     )
    #     return file_instance.save(override=self.context.get('override', False))  

@extend_schema(
    request=FileUploadSerializer,
    responses={201: {"status": 201, "responseText": "Files have been uploaded successfully"}, 403: {"status": 201, "responseText": "This action cannot be performed"}},
    description="Upload multiple files to a folder"
)
class FileUploadView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    def post(self, request):
        serializer = FileUploadSerializer(data=request.data)
        if serializer.is_valid():
            folder_id = serializer.validated_data.get('folder_id')
            if folder_id:
                folder = get_object_or_404(Folder, id=folder_id)
                if not folder.is_editor(request.user.id):
                    if folder.has_perm(request.user.id):
                        return Response({"responseText": "You do not have permission to upload"}, status=status.HTTP_403_FORBIDDEN)
                    return Response({"responseText": "This action cannot be performed"}, status=status.HTTP_403_NOT_FOUND)

            else:
                folder = None
            
        
            files = serializer.validated_data['files']
            override = serializer.validated_data['override']
            print("doing something..")

            for uploaded_file in files:
                file_instance = File(
                    name=uploaded_file.name,
                    owner=request.user,
                    parent=folder,
                    file=uploaded_file,
                    size=uploaded_file.size
                )
                file_instance.save(override=override)

                if folder:
                    if folder.owner != request.user:
                        if SharedFolder.objects.filter(folder=folder, shared_by=request.user).exists():
                            for sharing in SharedFolder.objects.filter(folder=folder, shared_by=request.user):
                                SharedFile.objects.get_or_create(
                                    user=sharing.user, 
                                    file=file_instance, 
                                    shared_by=request.user, 
                                    role=sharing.role
                                )
                        SharedFile.objects.get_or_create(
                            user=folder.owner, 
                            file=file_instance, 
                            shared_by=request.user, 
                            role=3
                        )

            return Response({"responseText": "Files have been uploaded successfully"}, status=status.HTTP_201_CREATED)
        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    url = serializers.URLField(required=True)

    def validate_email(self, value):
        # Ensure the email exists in the user model
        User = get_user_model()
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("This email address is not registered.")
        return value

@extend_schema(
    request=PasswordResetRequestSerializer,
    description="API for sending the verification email. URL field."
)
class PasswordResetRequestAPIView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)

        if serializer.is_valid():
            User = get_user_model()
            email = serializer.validated_data['email']
            user = User.objects.get(email=email)

            # Generate token and uidb64
            token = PasswordResetTokenGenerator().make_token(user)
            uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

            # Get the domain of the current site (needed for email)
            url = serializer.validated_data('url')
            self.send_reset(request, user, url, token, uidb64)
            return Response({'responseText': "Email sent successfully"})
        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        return Response(response, status=400)


    def send_reset(self, request, user, url, token, uidb64):
        url_tail = str({"token": f"{token}", "u_id": f"{uidb64}"}).encode("ascii")
        mail_subject = 'Activation link'  
        message = render_to_string('password_reset_email.html', {  
            'user': user,  
            'url': url,  
            'uid':urlsafe_base64_encode(url_tail),   
        })
        to_email = user.email
        plain_message = strip_tags(message)
        send_mail(mail_subject, plain_message, "verify@codedextersacademy.com", [to_email], html_message=message)

class FolderCreateSerializer(serializers.Serializer):
    folder_name = serializers.CharField(max_length=255, required=True)
    parent_folder_id = serializers.UUIDField(required=False)  # Optional, in case it's a nested folder

    def validate_folder_name(self, value):
        if not value:
            raise serializers.ValidationError("Folder name cannot be empty.")
        
        if self.parent_folder_id:
            try:
                parent_f = Folder.objects.get(id=self.parent)
                if Folder.objects.filter(name=self.folder_name, parent=parent_f).exists():
                    raise serializers.ValidationError("Folder with that name already exists")
            except:
                raise serializers.ValidationError("The Parent folder does not exist")        

        return value

class FolderCreateAPIView(APIView):
    serializer_class = FolderCreateSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    @extend_schema(
        request=FolderCreateSerializer,
        description="API for creating folder. Folder id will be required if folder is not created in root directory. Authentication required."
    )
    def post(self, request):
        serializer = FolderCreateSerializer(data=request.data)
        
        if serializer.is_valid():
            folder_name = serializer.validated_data['folder_name']
            parent_folder_id = serializer.validated_data.get('parent_folder_id', None)

            # Get the parent folder if provided
            if parent_folder_id:
                parent_folder = get_object_or_404(Folder, id=parent_folder_id)
                
                # Check if user has permission to add subfolder in the parent folder
                if not parent_folder.is_editor(request.user.id):
                    if parent_folder.has_perm(request.user.id):
                        return Response({"responseText": "You do not have permission to create subfolders here."}, status=status.HTTP_403_FORBIDDEN)
                    return Response({"responseText": "Parent folder not found."}, status=status.HTTP_404_NOT_FOUND)
            else:
                parent_folder = None  # No parent folder, it's a root-level folder
            
            # Create the new folder
            new_folder = Folder.objects.create(name=folder_name, parent=parent_folder, owner=request.user)

            # Handle shared folder logic (just like your initial code)
            if parent_folder and parent_folder.owner != request.user:
                if SharedFolder.objects.filter(shared_by=request.user, folder=parent_folder).exists():
                    for sharing in SharedFolder.objects.filter(shared_by=request.user, folder=parent_folder):
                        SharedFolder.objects.get_or_create(user=sharing.user, shared_by=request.user, folder=new_folder, role=sharing.role)
                
                SharedFolder.objects.get_or_create(user=parent_folder.owner, folder=new_folder, shared_by=request.user, role=3)

            return Response({"responseText": "Folder has been created successfully."}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetSerializer(serializers.Serializer):
    password1 = serializers.CharField(write_only=True, min_length=8, required=True)
    password2 = serializers.CharField(write_only=True, min_length=8, required=True)

    def validate(self, data):
        if data['password1'] != data['password2']:
            raise serializers.ValidationError("Passwords do not match.")
        return data

# Password Reset API view
@extend_schema(
    request=PasswordResetSerializer,
    description=""
)
class PasswordResetAPIView(APIView):
    permission_classes = [AllowAny]
    parser_classes = [JSONParser]

    def post(self, request, uidb64, token):
        serializer = PasswordResetSerializer(data=request.data)
        
        if serializer.is_valid():
            User = get_user_model()
            try:  
                uid = force_str(urlsafe_base64_decode(uidb64))  
                user = User.objects.get(pk=uid)  
            except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
                return Response({"responseText": "Invalid link"}, status=status.HTTP_400_BAD_REQUEST)
            
            if user is not None and PasswordResetTokenGenerator().check_token(user, token):
                # Reset user password
                user.set_password(serializer.validated_data['password1'])
                user.save()

                return Response({"responseText": "Password reset successful."}, status=status.HTTP_200_OK)
            else:
                return Response({"responseText": "Invalid token or user"}, status=status.HTTP_400_BAD_REQUEST)

        response = {'responseText': []}
        for key in serializer.errors.keys():
            for err in serializer.errors[key]:
                response['responseText'].append(err)
        return Response(response, status=status.HTTP_400_BAD_REQUEST)

def generate_download_signed_url(file, user, expiry_seconds=300):
    signer = TimestampSigner()
    value = f"{file.id}:{user.id}"
    signed_value = signer.sign(value)
    expiry_timestamp = timedelta(seconds=expiry_seconds).total_seconds()
    
    # Include the expiry time in the query parameters
    query_params = urlencode({'expiry': expiry_timestamp})
    url = reverse('serve_download_file', args=[signed_value])
    
    return f"{url}?{query_params}"

@login_required
def download_signed_file(request, signed_value):
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
            with open(encrypted_file_path, 'rb') as f:
                encrypted_content = f.read()
            decryptor = Fernet(key=settings.FILE_ENCRYPTION_KEY)
            decrypted_content = decryptor.decrypt(encrypted_content)

            # Serve the decrypted file for download (in-memory)
            response = FileResponse(decrypted_content, content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename="{file.name}"'
            return response
        else:
            return HttpResponseForbidden("You do not have permission to access this file.")
    
    except SignatureExpired:
        return HttpResponseForbidden("This link has expired.")
    
    except BadSignature:
        return HttpResponseForbidden("Invalid URL.")


class FileDownloadSerializer(serializers.Serializer):
    file_id = serializers.UUIDField(help_text="ID of the file to download")


@extend_schema(
    request=FileDownloadSerializer,
    description="API for downloading files.",

)
@api_view(['GET'])
def download_file(request):
    file_id = request.GET.get('file_id')
    if not file_id:
        return Response({"status": 403, "responseText": "File id is required"})
    file = get_object_or_404(File, id=file_id)
    if request.user.is_authenticated:
        # Get the file object

        # Check if the user has permission to access the file
        if not file.has_perm(request.user.id):
            return HttpResponseForbidden("You do not have permission to access this file.")
        
        
        url = generate_download_signed_url(file, request.user)
        return redirect(to=url)
    else:
        if file.access_everyone:
            url = generate_download_signed_url(file, request.user)
            return redirect(to=url)
        return HttpResponseForbidden("You do not have permission to access this file.")

class FileSerializer(serializers.ModelSerializer):
    class Meta:
        model = File
        fields = ['id', 'name', 'size', 'created_at', 'updated_at', 'owner', 'starred']

class FolderSerializer(serializers.ModelSerializer):

    class Meta:
        model = Folder
        fields = ['id', 'name', 'owner', 'created_at']

    def get_subfolders(self, obj):
        # Serializing the subfolders of the folder
        subfolders = obj.subfolders.all()
        return FolderSerializer(subfolders, many=True).data

    def get_files(self, obj):
        # Serializing the files within the folder
        files = obj.subfiles.all()
        return FileSerializer(files, many=True).data
    
class FolderViewSerializer(serializers.Serializer):
    folder_id = serializers.CharField()

@extend_schema(
    request=FolderViewSerializer
)
class FolderViewAPIView(APIView):
    serializer_class = FolderViewSerializer
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        folder_id = request.GET.get('folder_id')
        folder = get_object_or_404(Folder, id=folder_id)

        # Check if the user has permission to access the folder
        if folder.has_perm(request.user.id):
            
            # Increase access count if the folder owner is the current user
            if folder.owner == request.user:
                folder.access_count += 1
                folder.save()

            # Serialize the folder, its subfolders, and files
            serializer = FolderSerializer(folder)
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response({"responseText": "You do not have permission to view this folder."}, status=status.HTTP_403_FORBIDDEN)

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

class ShareFolderAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        folder_instance = get_object_or_404(Folder, id=folder_id)

        # Check if the user has permission to share the folder
        if folder_instance.is_editor(request.user.id):
            usernames = request.data.get('usernames', '')
            share_with_everyone = request.data.get('everyone', False)
            friend_to_share = request.data.get('friends', [])
            role = request.data.get('userRole', 1)  # Default role is Viewer (1)

            # Parse the usernames and friends list
            usernames = [username.strip() for username in usernames.split(',') if username.strip()]
            for friend in friend_to_share:
                try:
                    usernames.append(CustomUser.objects.get(username=friend).username)
                except:
                    pass
            messages = []

            # If not sharing with everyone
            if not share_with_everyone:
                if folder_instance.access_everyone:
                    messages.append("This folder has been removed from everyone's view")
                folder_instance.access_everyone = False
                folder_instance.save()

                # Share with specific users
                for username in usernames:
                    user = CustomUser.objects.filter(username=username).first()
                    if user and user != request.user:
                        try:
                            shared_folder, created = SharedFolder.objects.get_or_create(
                                user=user,
                                folder=folder_instance,
                                defaults={
                                    'shared_by': request.user,
                                    'role': role
                                }
                            )
                            if not created:
                                # Update if already shared
                                shared_folder.shared_by = request.user
                                shared_folder.role = role
                                shared_folder.save()

                            share_item_recursive(folder_instance, user, request.user)
                            messages.append(f'{folder_instance.name} shared with {user.username}')
                        except Exception as e:
                            messages.append(f'Failed to share with {username} due to: {str(e)}')
                    else:
                        messages.append(f'Failed to share with {username} (invalid username or sharing with yourself).')
            else:
                # Share with everyone
                folder_instance.access_everyone = True
                folder_instance.save()
                messages.append(f'{folder_instance.name} shared with everyone')

            return Response({'status': 200, 'responseText': 'Folder shared with selection'}, status=status.HTTP_200_OK)

        return Response({'status': 403, 'responseText': 'You do not have permission to share this folder'}, status=status.HTTP_403_FORBIDDEN)

    def get(self, request):
        folder_id = request.GET.get('folder_id')
        folder_instance = get_object_or_404(Folder, id=folder_id)

        # Check permissions for viewing the shared users
        if folder_instance.is_editor(request.user.id):
            shared_list = SharedFolder.objects.filter(shared_by=request.user, folder=folder_instance)
            shared_with_everyone = folder_instance.access_everyone

            return Response({
                'folder_name': folder_instance.name,
                'shared_list': [
                    {
                        'user': shared.user.username,
                        'role': shared.get_role_display(),
                    } for shared in shared_list
                ],
                'shared_with_everyone': shared_with_everyone,
            }, status=status.HTTP_200_OK)

        return Response({'status': 403, 'responseText': 'You do not have permission to view shared users'}, status=status.HTTP_403_FORBIDDEN)

class StarFolderSerializer(serializers.Serializer):
    folder_id = serializers.CharField()

class StarFolderAPIView(APIView):
    serializer_class = StarFolderSerializer
    parser_classes = [JSONParser]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        try:
            folder = Folder.objects.get(id=request.user)
            if request.user != folder.owner:
                if not (folder.access_list.contains(request.user) or folder.access_everyone or SharedFolder.objects.filter(folder=folder, user=request.user).exists()):
                    return Response({"status": 403, "responseText": "You do not have access to this item"}, status=403)
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
            return Response({"status": 200, "responseText": "This folder has been successfully starred"}, status=200)        
        except:
            return Response({"status": 404, "responseText": "This folder cannot be found"}, status=404)

class BinFolderSerializer(serializers.Serializer):
    folder_id = serializers.CharField()

class BinFolderAPIView(APIView):
    serializer_class = BinFolderSerializer
    parser_classes = [JSONParser]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        try:
            folder = Folder.objects.get(id=folder_id)
            if request.user != folder.owner:
                if not folder.has_perm(request.user.id):
                    return  Response({"status": 403, "responseText": "You do not have permission to access this file"}, status=403)
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
            return Response({"status": 200, "responseText": "This folder has been successfully binned"}, status=200)
        except:
            return Response({"status": 404, "responseText": "This folder was not found"})

class DeletePermAPIView(APIView):
    serializer_class = StarFolderSerializer
    parser_classes = [JSONParser]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        try:
            folder = Folder.objects.get(id=folder_id)
            if folder.owner == request.user:
                folder.delete()
                return Response({"status": 200, "responseText": "This folder has been successfully deleted"}, status=200)
            elif folder.has_perm(request.user.id):
                folder.deny_access(request.user.id)
                return Response({"status": 200, "responseText": "You have deniec your access to this folder"})
            else:
                return Response({"status": 403, "responseText": "You do not have access to this folder"}, status=403)
        except:
            return Response({"status": 404, "responseText": "This folder was not found."}, status=404)
        
class CopySharedFolderAPIView(APIView):
    serializer_class = StarFolderSerializer
    parser_classes = [JSONParser]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        try:
            folder_instance =   Folder.objects.get(id=folder_id)
            if not folder_instance.has_perm(request.user.id):
                return Response({"status": 403, "responseText": "You do not have access to this folder"}, status=403)

            folder_directory = os.path.join(settings.MEDIA_ROOT, folder_instance.get_path())

            root_folder = Folder.objects.create(
                name=folder_instance.name,
                parent=None,
                owner=request.user
            )
    
            root_path = os.path.join(settings.MEDIA_ROOT, root_folder.get_path())
            shutil.copytree(folder_directory, root_path, dirs_exist_ok=True)

            for root, dirs, files in os.walk(folder_directory):
                relative_path = os.path.relpath(root, folder_directory)
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

                    File.objects.create(
                        name=file_name,
                        file=relative_file_path,
                        owner=request.user,
                        parent=parent_folder,
                        size=file_size  # Set the file size
                    )
            return Response({"status": 200, "responseText": "This folder has been copied to your drive"})
        except Exception as e:
            return Response({"status": 404, "responseText": "This folder does not exist."}, status=404)

encryptor = Fernet(settings.FILE_ENCRYPTION_KEY)
def is_binary_file(file_path, block_size=512):
    """
    Check whether a file is binary or text by reading its content.
    Reads a portion of the file and checks if it's mostly ASCII or UTF-8.
    """
    with open(file_path, 'rb') as file:
        block = file.read(block_size)
        if b'\0' in block:
            return True  # If there are null bytes, it is likely a binary file.
        
        # Try to detect the encoding of the file
        result = chardet.detect(block)
        encoding = result['encoding']
        
        if encoding is None:
            return True  # If no encoding detected, assume binary
        
        # Check if encoding is UTF-8 or other text-based encoding
        try:
            block.decode(encoding)
            return False  # Successfully decoded, so it's a text file
        except (UnicodeDecodeError, LookupError):
            return True 
def get_image_extension(image_data):
    from PIL import Image
    import io
    image = Image.open(io.BytesIO(image_data))
    return image.format.lower()
def decrypt_chunks(file_instance):
    cipher_suite = Fernet(settings.FILE_ENCRYPTION_KEY)
    with open(file_instance.file.path, 'rb') as encrypted_file:
        while True:
            chunk = encrypted_file.read(8192)  # Read file in chunks
            if not chunk:
                break
            yield cipher_suite.decrypt(chunk)

def convert_image(image_data, file_id):
    from PIL import Image
    import io
    # Create a hash of the image data
    image_hash = hashlib.md5(image_data).hexdigest()

    image_extension = get_image_extension(image_data)
    image_name = f'{image_hash}.{image_extension}'
    # Set the image path using the hash
    image_path = apply_correct_path(os.path.join('secure_doc_media', f'{image_hash}.{image_extension}'))

    # Check if the image already exists
    if os.path.exists(image_path):
        return reverse('serve_img', args=[file_id, image_name])
    
    default_storage.save(image_path, io.BytesIO(image_data))

    # Create the image if it doesn't exist

    return reverse('serve_img', args=[file_id, image_name])

def process_html_for_secure_images(html_content, file_id):
    from bs4 import BeautifulSoup
    import requests

    soup = BeautifulSoup(html_content, 'html.parser')

    for img_tag in soup.find_all('img'):
        img_url = img_tag['src']
        if img_url.startswith('data:image'):
            header, encoded = img_url.split(",", 1)
            image_data = base64.b64decode(encoded)
            secure_image_url = convert_image(image_data, file_id)
            img_tag['src'] = secure_image_url
        else:
            response = requests.get(img_url)
            if response.status_code == 200:
                image_data = response.content
                secure_image_url = convert_image(image_data, file_id)
                img_tag['src'] = secure_image_url

    return str(soup)

@login_required
def serve_secure_doc_image(request, image_name, file_id):
    # Get the file object
    file = get_object_or_404(File, id=file_id)
    # Construct the image path
    image_path = apply_correct_path(os.path.join('secure_doc_media', image_name))

    # Check if the image exists
    if not os.path.exists(image_path):
        raise Http404("Image not found")

    # Serve the image securely
    if file.has_perm(request.user.id):
        return FileResponse(open(image_path, 'rb'))
    return HttpResponseForbidden("You cannot view this image")

def secure_image_urls(document_html, file_id):
    # Regex pattern to find image URLs
    pattern = re.compile(r'<img src="([^"]+)"')
    
    # Replace image URLs with a secure Django view URL
    def replace_url(match):
        original_url = match.group(1)
        # Generate a secure URL to serve the image
        secure_url = reverse('serve_img', args=[file_id, original_url.split('/')[-1]])
        return f'<img src="{secure_url}"'
    
    return re.sub(pattern, replace_url, document_html)

def generate_signed_url(file, user, expiry_seconds=300):
    signer = TimestampSigner()
    value = f"{file.id}:{user.id}"
    signed_value = signer.sign(value)
    expiry_timestamp = timedelta(seconds=expiry_seconds).total_seconds()
    
    # Include the expiry time in the query parameters
    query_params = urlencode({'expiry': expiry_timestamp})
    url = reverse('serve_signed_file', args=[signed_value])
    
    return f"{url}?{query_params}"

class ShareFileAPIView(APIView):
    parser_classes = [JSONParser]

    def post(self, request):
        folder_id = request.POST.get('folder_id')
        try:
            file_instance = File.objects.get(id=folder_id)
            if request.method == 'POST':
                usernames = request.POST.get('usernames', '')
                role = request.POST.get('userRole', '1')
                share_with_everyone = request.POST.get('everyone', False)
                friend_to_share = request.POST.getlist('friends')
            
                usernames = [username.strip() for username in usernames.split(',') if username.strip() and CustomUser.objects.filter(username=username.strip()).exists()]
            
                for friend in friend_to_share:
                    try:
                        usernames.append(CustomUser.objects.get(id=friend).username)
                    except:
                        pass
                # print(usernames)

                messages = []
                if not share_with_everyone:
                    for username in usernames:
                        user = CustomUser.objects.filter(username=username).first()
                        print(file_instance)
                        file_instance.access_list.add(user)
                        print(file_instance.access_list.all())
                        file_instance.save()
                        if user and user != request.user:
                            try:
                                SharedFile.objects.update_or_create(
                                    user=user,
                                    file=file_instance,
                                    shared_by=request.user,
                                    role=role
                                )
                            except:
                                pass
                            messages.append(f'{file_instance.name} shared with {user.username}')
                        else:
                            messages.append(f'Failed to share with {username} (invalid username or sharing with yourself).')
                else:
                    file_instance.access_everyone = True
                    file_instance.save()
                    messages.append(f'{file_instance.name} shared with everyone')

            return JsonResponse({'status': 'success', 'messages': "File shared with selected users."})
        except:
            return Response({"status": 404, "responseText": "This file was not found."})

class FileBaseSerializer(serializers.Serializer):
    file_id = serializers.UUIDField()

class StarFileAPIView(APIView):
    serializer_class = FileBaseSerializer
    parser_classes = [JSONParser]

    def post(self, request):
        file_id = request.POST.get('file_id')
        serializer = self.serializer_class(file_id)
        if serializer.is_valid():
            try:
                file = File.objects.get(id=file_id)
                if not file.has_perm(request.user.id):
                    return Response({"status": 403, "responseText": "Action denied"})
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
                return Response({"status": 200, "responseText": "This file has been starred." if file.starred or request.user.starred_files.contains(file) else "This file has been unstarred"})
            except:
                return Response({"status": 404, "responseText": "This file was not found"}, status=404)
            

# # Create your views here.
# def sign_up(request):
#     if request.method == 'POST':
#         form = RegistrationForm(request.POST)
#         if form.is_valid():
#             user = CustomUser.objects.create(username=request.POST.get('username'), full_name=request.POST.get('full_name'), email=request.POST.get('email'))
#             user.set_password(request.POST.get('password'))
#             user.is_active = False
#             user.save()
#             return JsonResponse(createBasicResponse(status=200, responseText="Check Your Email For Verification"), status=200)

#         return JsonResponse(createBasicResponse(status=302, responseText="There was an error", data=form.errors), status=302)
#     return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)

# def activate(request):
#     if request.method == "POST":
#         User = get_user_model()
#         uidb64 = request.POST.get('uidb64')
#         token = request.POST.get('token')  
#         try:  
#             uid = force_str(urlsafe_base64_decode(uidb64))  
#             user = User.objects.get(pk=uid)  
#         except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
#             user = None  
#         if user is not None and account_activation_token.check_token(user, token):  
#             user.is_active = True  
#             user.save()  
#             return JsonResponse({"status": "success", "msg": "Account has been activated"}, status=200) 
#         else:  
#             return JsonResponse(createBasicResponse(status=403, data="", responseText="Invalid URL"), status=403)
#     return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)

# def login(request):
#     if request.method == "POST":
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         user = authenticate(username, password)
#         if user is not None:
#             login(request, user)
#             return JsonResponse(createBasicResponse(status=200, responseText="You have been logged in"), status=200)
#         else:
#             return JsonResponse(createBasicResponse(status=400, responseText="Invalid Username or Pass"), status=400)
#     return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)