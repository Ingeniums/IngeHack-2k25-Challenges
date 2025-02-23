from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
from .forms import RegisterForm, LoginForm
from .decorators import throttle
from django.views.decorators.csrf import csrf_exempt

# Register View
@csrf_exempt
def register_view(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()  # Save the user to the database
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}')
            login(request, user)  # Log in the user immediately after registration
            return redirect('quote_list')  # Redirect to the home page or any other page
    else:
        form = RegisterForm()
    return render(request, 'register.html', {'form': form})

# Login View
@csrf_exempt
@throttle(limit=5, period=60) 
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome {username}!')
                return redirect('quote_list')  # Redirect to home or other page after login
            else:
                messages.error(request, 'Invalid username or password')
        else:
            messages.error(request, 'Invalid username or password')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

# Logout View
@csrf_exempt
def logout_view(request):
    logout(request)
    messages.success(request, 'You have successfully logged out.')
    return redirect('login')  # Redirect to login page after logout
