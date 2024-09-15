from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

class EmailOrUsernameModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        UserModel = get_user_model()
        if username is None:
            username = kwargs.get(UserModel.USERNAME_FIELD)
        try:
            # Check if the username is an email
            user = UserModel.objects.get(email=username)
        except UserModel.DoesNotExist:
            # If not, try to get the user by username
            try:
                user = UserModel.objects.get(username=username)
            except UserModel.DoesNotExist:
                # No user found with this username or email
                return None

        # Check the password
        if user.check_password(password) and self.user_can_authenticate(user):
            return user
        return None
