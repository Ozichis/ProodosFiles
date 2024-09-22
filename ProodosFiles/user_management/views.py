import os
from django.conf import settings
from django.http import Http404, HttpResponse, HttpResponseForbidden, HttpResponseRedirect, JsonResponse  
from django.shortcuts import get_object_or_404, render, redirect  
from django.contrib.auth import login, authenticate, get_user_model, logout
from django.contrib.auth.decorators import login_required
from django.contrib.sites.shortcuts import get_current_site
from django.contrib import messages
from django.utils.encoding import force_bytes, force_str  
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode  
from django.utils.html import strip_tags
from django.template.loader import render_to_string

from file_management.models import File
from folder_management.models import Folder  
from .token import account_activation_token, password_reset_token 
from .models import CustomUser, FriendRequest, FriendShip
from .forms import RegistrationForm
from django.core.mail import EmailMessage, send_mail 

def login(request):
    return render(request, "Login.html", {})

def register(request):
    return render(request, 'Register.html', {})

def activate(request):  
    return render(request, "Activation.html", {})
    


def forgot_password(request):
    if request.method == 'POST':
        if CustomUser.objects.filter(email=request.POST.get('username')).exists():
            user = CustomUser.objects.get(email=request.POST.get('username'))
            current_site = get_current_site(request)  
            mail_subject = 'Password Reset Link'  
            message = render_to_string('password_reset_email.html', {  
                    'user': user,  
                    'domain': current_site.domain,  
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                    'token':account_activation_token.make_token(user),  
            })
            to_email = request.POST.get('username')
            plain_message = strip_tags(message)
            send_mail(mail_subject, plain_message, "em@codedextersacademy.com", [to_email], html_message=message)
            return JsonResponse({'success':True, "ok": True, "result": "success", "msg": "success"}, status=200)
        elif CustomUser.objects.filter(username=request.POST.get('username')).exists():
            user = CustomUser.objects.get(username=request.POST.get('username'))
            current_site = get_current_site(request)  
            mail_subject = 'Password Reset Link'  
            message = render_to_string('password_reset_email.html', {  
                    'user': user,  
                    'domain': current_site.domain,  
                    'uid':urlsafe_base64_encode(force_bytes(user.pk)),  
                    'token':account_activation_token.make_token(user),  
            })
            to_email = str(user.email)
            plain_message = strip_tags(message)
            send_mail(mail_subject, plain_message, "em@codedextersacademy.com", [to_email], html_message=message)
            return JsonResponse({'success':True, "ok": True, "result": "success", "msg": "success"}, status=200)
        print('Exists')
        return JsonResponse({'success':False, "ok": False, "result": "error", "msg": "Username or Email does not exists"}, status=302)
    return render(request, "password_reset_form.html", {})

def password_reset(request, uidb64, token):
    if request.method == "POST":
        User = get_user_model()
        try:  
            uid = force_str(urlsafe_base64_decode(uidb64))  
            user = User.objects.get(pk=uid)  
        except(TypeError, ValueError, OverflowError, User.DoesNotExist):  
            user = None
        if user is not None and password_reset_token.check_token(user, token):
            user.set_password(request.POST.get("password1"))
            user.save()
            print("Password reset successful")
            return JsonResponse({"success": True, "ok": True, "result": "success", "msg": "success"}, status=200)
        else:
            return render(request, "password_reset_failed.html", {})
    return render(request, "password_resetting.html", {})



def send_friend_request(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        try:
            to_user = CustomUser.objects.get(username=username)
        except CustomUser.DoesNotExist:
            messages.error(request, "This user does not exist. Check that the username is spelt correctly")
            return redirect('friends_list')
        from_user = request.user

        if from_user == to_user:
            messages.error(request, "You cannot send a friend request to yourself.")
            return redirect("friends_list")

        if FriendShip.objects.filter(user=from_user, friend=to_user).exists() or FriendShip.objects.filter(user=to_user, friend=from_user).exists():
            messages.error(request, "You are already friends.")
            return redirect("friends_list")

        friend_request, created = FriendRequest.objects.get_or_create(from_user=from_user, to_user=to_user)

        if created:
            return redirect('friends_list')
        else:
            messages.error(request, "Friend request already sent.")
            return redirect("friends_list")
 
@login_required
def accept_friend_request(request, request_id):
    friend_request = get_object_or_404(FriendRequest, id=request_id)

    if friend_request.to_user != request.user:
        messages.error(request, "This request does not belong to you.")
        return render("friends_list")

    friend_request.accept()
    return redirect('friends_list')

@login_required
def decline_friend_request(request, request_id):
    friend_request = get_object_or_404(FriendRequest, id=request_id)

    if friend_request.to_user != request.user:
        return HttpResponseForbidden("This request does not belong to you.")

    friend_request.decline()
    return redirect('friends_list')

@login_required
def friends_list(request):
    friends = request.user.friends.all()
    from_friend_requests = request.user.received_requests.all()
    to_friend_requests = request.user.sent_requests.all()

    return render(request, 'friends_list.html', {'friends': friends, 'from_friend_requests': from_friend_requests, 'to_friend_requests': to_friend_requests, 'user': request.user})

@login_required
def remove_friend(request, friend_id):
    friend = get_object_or_404(FriendShip, id=friend_id)
    if not (friend.user == request.user or friend.friend == request.user):
        messages.error(request, "There was an error. Try removing your own requests instead")
        return redirect("friends_list")
    friend.delete()
    return redirect('friends_list')

@login_required
def log_out(request):
    logout(request)
    return redirect('homepage')

