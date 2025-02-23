from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User

# User Registration Form
class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']

# Login Form (if you want to customize it)
class LoginForm(AuthenticationForm):
    username = forms.CharField(label='Username', max_length=255)
    password = forms.CharField(widget=forms.PasswordInput)
