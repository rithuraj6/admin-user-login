from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.cache import never_cache
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import re

# <--- Admin Panel --->

@never_cache
def admin_login(request):
    error=''
    if request.user.is_authenticated and request.session.get('is_admin'):
        return redirect('adminpanel')                                                       

    if request.user.is_authenticated and request.session.get('is_admin'):
        messages.info(request, 'Already logged in as admin.')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        if not username or not password:
            error='both fields are required'
        

        user = authenticate(request, username=username, password=password)
        if user and user.is_staff:
            login(request, user)
            request.session['is_admin'] = True
            next_url = request.GET.get('next', '') 
            return redirect(next_url or 'adminpanel') 
        else:
            
            error= 'Invalid or non-admin credentials.'
           
        
    context={
        'error':error,
    }

    return render(request, 'admin_login.html',context)


@never_cache
def admin_logout(request):
    logout(request)
    return redirect('adminlogin')

@never_cache
def admin_panel(request):
    if not request.user.is_superuser and not request.user.is_authenticated:
        return redirect('adminlogin')

    search_query = request.GET.get('search', '')
    users = User.objects.filter(username__icontains=search_query)
  

    return render(request, 'adminpanel.html', {'users': users, 'search_query': search_query})

@never_cache
def edit_user(request, user_id):
    
    if not request.user.is_superuser:
        return redirect('adminlogin')
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        username = request.POST.get('username', user.username).strip()
        email = request.POST.get('email', user.email).strip()
        password = request.POST.get('password', '')
        is_staff = request.POST.get('is_staff') == 'on'

        if User.objects.filter(username=username).exclude(id=user_id).exists():
            messages.error(request, 'Username taken.')
            
        if User.objects.filter(email=email).exclude(id=user_id).exists():
            messages.error(request, 'Email taken.')
           

        user.username = username
        user.email = email
        if password:
            user.set_password(password)
        user.is_staff = is_staff
        user.is_active = request.POST.get('is_active') == 'on' 
        user.save()
        messages.success(request, 'User updated.')
        return redirect('adminpanel')

    return render(request, 'edit_user.html', {'user_obj': user})

@never_cache
def delete_user(request, user_id):
    if not request.session.get('is_admin'):
        return redirect('adminlogin')
    user = get_object_or_404(User, id=user_id)
    if user.id == request.user.id:
        messages.error(request, "Cannot delete self.")
        return redirect('adminpanel')

    if request.method == 'POST':
        user.delete()
        messages.success(request, 'User deleted.')
        return redirect('adminpanel')

    return render(request, 'delete.html', {'user_obj': user})

@never_cache
def create_user(request):
    if not request.session.get('is_admin'):
        return redirect('adminlogin')

    context = {}  # Build context progressively
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        is_staff = request.POST.get('is_staff') == 'on'
        is_active = request.POST.get('is_active') == 'on'

        errors = []
        if not all([username, email, password]):
            errors.append('Username, email, password required.')
        if len(username) < 4:  # Added length validation
            errors.append('Username too short (min 3 chars).')
        if len(password) < 6:
            errors.append('Password too short (min 6 chars).')
        if User.objects.filter(username=username).exists():
            errors.append('Username exists.')
        if User.objects.filter(email=email).exists():
            errors.append('Email exists.')
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):  # Added email regex
            errors.append('Invalid email format.')

        if errors:
            for error in errors:
                messages.error(request, error)
        else:
            user = User.objects.create_user(username=username, email=email, password=password)
            user.is_staff = is_staff
            user.is_active = is_active
            user.save()
            messages.success(request, 'User created.')
            return redirect('adminpanel')

    return render(request, 'create_user.html', context)

@never_cache
def block_unblock_user(request, user_id):
    if not request.session.get('is_admin'):
        return redirect('adminlogin')
    user = get_object_or_404(User, id=user_id)
    if user.id == request.user.id:
        messages.error(request, "Cannot block self.")
        return redirect('adminpanel')

    if request.method == 'POST':
        user.is_active = not user.is_active
        user.save()
        status = "blocked" if not user.is_active else "unblocked"
        messages.success(request, f"User {status}.")
        return redirect('adminpanel')

    return render(request, 'block_unblockuser.html', {'user_obj': user})



# <--- User Side --->

@never_cache
def login_page(request):
    if request.user.is_authenticated and not request.session.get('is_admin'):
        return redirect('home')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')

        if not username or not password:
            messages.error(request, 'Both required.')
            return render(request, "login.html")

        user = authenticate(request, username=username, password=password)
        if user:
            if user.is_staff:
                messages.error(request, 'Use admin login.')
                return render(request, "login.html")
            login(request, user)
            request.session['is_user'] = True
            return redirect('home')
        else:
            messages.error(request, 'Invalid credentials.')
            return render(request, "login.html")

    return render(request, "login.html")

@never_cache
def signup_page(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username exists. Log in.")
            return render(request, "signup.html") 

        if not all([username, email, password, confirm_password]):
            messages.error(request, 'All fields required.')
            return render(request, "signup.html")

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            messages.error(request, 'Invalid email.')
            return render(request, "signup.html")

        if User.objects.filter(email=email).exists():
            messages.error(request, 'Email registered.')
            return render(request, "signup.html")

        if len(password) < 6:
            messages.error(request, 'Password too short.')
            return render(request, "signup.html")

        if password != confirm_password:
            messages.error(request, 'Passwords mismatch.')
            return render(request, "signup.html")

        user = User.objects.create_user(username=username, email=email, password=password)
        user.is_active = True  
        user.save()
        messages.success(request, 'Signup successful! Log in.')
        return redirect('login')

    return render(request, "signup.html")

@never_cache
@login_required(login_url='login')
def home(request):
    return render(request, "home.html", {'current_user': request.user})
@never_cache
@login_required(login_url='login')
def about(request):
    return render(request, "about.html")

@never_cache
@login_required(login_url='login')
def contact(request):
    return render(request, "contact.html")

def logout_user(request):
    if request.session.get('is_user'):
        request.session.pop('is_user')
    logout(request)  
    messages.success(request, "You have logged out successfully.") 
    return redirect('login')
