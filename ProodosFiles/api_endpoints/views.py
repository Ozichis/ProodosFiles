from rest_framework import serializers, generics, views, status
from rest_framework.permissions import AllowAny
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView

from django.http import JsonResponse
from django.shortcuts import get_object_or_404, render
from django.core.validators import RegexValidator

from user_management.forms import RegistrationForm
from user_management.models import CustomUser

from django.contrib.sites.shortcuts import get_current_site
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator

from django.core.mail import send_mail

from django.template.loader import render_to_string

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.html import strip_tags
from django.utils.encoding import force_bytes, force_str

from user_management.token import account_activation_token

from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from drf_spectacular.utils import extend_schema, OpenApiParameter
from drf_spectacular.types import OpenApiTypes



def createBasicResponse(status=200, responseText='', data=''):
    return {'status': status, 'responseText': responseText, 'data': data}

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    url = serializers.CharField()

    
    class Meta:
        model = CustomUser
        fields = ['username', 'full_name', 'email', 'password', 'url']

    def create(self, validated_data):
        user = CustomUser.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            is_active=False  # Prevent login until email is verified
        )
        user.set_password(validated_data['password'])
        user.save()
        self.send_verification(self.context['request'], user, self.url)

    def send_verification(self, request, user, url):
        current_site = get_current_site(request)  
        mail_subject = 'Activation link'  
        message = render_to_string('acc_active_email.html', {  
            'user': user,  
            'url': url,  
            'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
            'token':account_activation_token.make_token(user),  
        })
        to_email = request.POST.get('email')
        plain_message = strip_tags(message)
        send_mail(mail_subject, plain_message, "ebipadenice@outlook.com", [to_email], html_message=message)
            
class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        # Call the serializer to create the user
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        # Send success response after registration
        return Response(
            {
                "data": "",
                "responseText": "Registration successful. Please check your email to verify your account.",
                # "user": {
                #     "username": user.username,
                #     "email": user.email
                # }
            }, 
            status=status.HTTP_201_CREATED
        )
    

class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField()

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')
        user = authenticate(username=username, password=password)

        if user and user.is_active:
            return user
        raise serializers.ValidationError("Invalid credentials or account not activated.")


class LoginView(APIView):
    serializer_class = LoginSerializer  # Specify the serializer class

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data
            token, created = Token.objects.get_or_create(user=user)
            return Response({'token': token.key})
        return Response(serializer.errors, status=400)
    

User = get_user_model()

class VerifyEmailSerializer(serializers.Serializer):
    uidb64 = serializers.UUIDField()
    token = serializers.CharField()

    def validate(self, data):
        uidb64 = data.get('uidb64')
        token = data.get('token')
        try:
            uid = urlsafe_base64_decode(uidb64).decode()
            user = get_object_or_404(User, pk=uid)
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):
            user = None

        if default_token_generator.check_token(user, token):
            return user
        return None
        
class VerifyEmailView(views.APIView):
    serializer_class = VerifyEmailSerializer
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        serializer = self.serializer_class(data=request.data)

        if serializer.is_valid():
            user = serializer.validated_data
            user.is_active = True
            user.save()
            return Response({'responseText': 'Email verified successfully'}, status=status.HTTP_200_OK)
        return Response({'responseText': 'Invalid token or user'}, status=status.HTTP_400_BAD_REQUEST)
    
# Create your views here.
def sign_up(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            user = CustomUser.objects.create(username=request.POST.get('username'), full_name=request.POST.get('full_name'), email=request.POST.get('email'))
            user.set_password(request.POST.get('password'))
            user.is_active = False
            user.save()
            return JsonResponse(createBasicResponse(status=200, responseText="Check Your Email For Verification"), status=200)

        return JsonResponse(createBasicResponse(status=302, responseText="There was an error", data=form.errors), status=302)
    return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)

def activate(request):
    if request.method == "POST":
        User = get_user_model()
        uidb64 = request.POST.get('uidb64')
        token = request.POST.get('token')  
        try:  
            uid = force_str(urlsafe_base64_decode(uidb64))  
            user = User.objects.get(pk=uid)  
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
            user = None  
        if user is not None and account_activation_token.check_token(user, token):  
            user.is_active = True  
            user.save()  
            return JsonResponse({"status": "success", "msg": "Account has been activated"}, status=200) 
        else:  
            return JsonResponse(createBasicResponse(status=403, data="", responseText="Invalid URL"), status=403)
    return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)

def login(request):
    if request.method == "POST":
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(username, password)
        if user is not None:
            login(request, user)
            return JsonResponse(createBasicResponse(status=200, responseText="You have been logged in"), status=200)
        else:
            return JsonResponse(createBasicResponse(status=400, responseText="Invalid Username or Pass"), status=400)
    return JsonResponse(createBasicResponse(status=103, responseText="No POST request"), status=103)