import hashlib
import logging

import requests
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib.auth.models import User
from django.db import connection
from django.utils.timezone import now
from django_ratelimit.decorators import ratelimit


def index(request):
    return HttpResponse("Hello, world")


from django.contrib.auth import authenticate, login
from django.http import HttpResponse, JsonResponse
from django.shortcuts import render, redirect


def signin(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')  # Redirect to a success page.
        else:
            return HttpResponse("Invalid login")
    else:
        return render(request, 'signin.html')


def owasp1_insecure(request):
    user_id = request.GET.get('user_id')
    user = User.objects.get(pk=user_id)

    return HttpResponse(f"Hello, {user.email}")


def owasp1_secure(request):
    if not request.user.is_authenticated:
        return HttpResponse("Unauthorized")

    return HttpResponse(f"Hello, {request.user.email}")

@login_required(login_url="signin/")
def change_password_secure(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user = form.save()
            # Secure password hash
            update_session_auth_hash(request, user)  
            return redirect('signin/')
    else:
        form = PasswordChangeForm(request.user)
    return render(request, 'change_password.html', {'form': form})

@login_required(login_url="signin/")
def change_password_insecure(request):
    if request.method == 'POST':
        new_password = request.POST.get('new_password')
        # Insecure password hashing
        hashed_password = hashlib.md5(new_password.encode()).hexdigest()
        request.user.password = hashed_password
        request.user.save()
        return redirect('signin/')
    return render(request, 'change_password_insecure.html')


# http://localhost:8000/main/owasp3_insecure?product_name=product1
# http://localhost:8000/main/owasp3_insecure?product_name=product1='; DROP TABLE delete_me; --
# http://localhost:8000/main/owasp3_insecure?product_name=product1' OR '1'='1
def owasp3_insecure(request):
    product_name = request.GET.get('product_name')
    query = f"SELECT * FROM main_product WHERE name = '{product_name}'"
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()

    products = [row for row in rows]
    return HttpResponse(str(products))


# http://localhost:8000/main/owasp3_secure?product_name=product1
# http://localhost:8000/main/owasp3_secure?product_name=product1='; DROP TABLE delete_me; --
# http://localhost:8000/main/owasp3_secure?product_name=product1' OR '1'='1
def owasp3_secure(request):
    product_name = request.GET.get('product_name')
    query = "SELECT * FROM main_product WHERE name = %s"
    with connection.cursor() as cursor:
        cursor.execute(query, [product_name])
        rows = cursor.fetchall()

    products = [row for row in rows]
    return HttpResponse(str(products))

def owasp7_insecure(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return HttpResponse("Logged in successfully.")
        else:
            return HttpResponse("Invalid login attempt.")
    else:
        return render(request, 'signin.html')
@ratelimit(key='post:username', rate='2/m', block=True, method=['POST'])
# @ratelimit(key='ip', rate='10/m', block=True, method=['POST'])
def owasp7_secure(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return HttpResponse("Logged in successfully.")
        else:
            return HttpResponse("Invalid login attempt.")
    else:
        return render(request, 'signin.html')

def owasp8_insecure(request):
    try:
        # Get the uploaded file from the request
        uploaded_file = request.FILES['file']
        
        # Save the file to the server without integrity verification
        # file_path = save_uploaded_file(uploaded_file)
        
        return JsonResponse({'success': 'File uploaded successfully'})
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
def owasp8_secure(request):
    try:
        # Get the uploaded file from the request
        uploaded_file = request.FILES['file']
        
        # Calculate the checksum of the uploaded file
        sha256_hash = hashlib.sha256()
        for chunk in uploaded_file.chunks():
            sha256_hash.update(chunk)
        calculated_checksum = sha256_hash.hexdigest()
        
        # Verify the integrity of the file by comparing checksums
        if calculated_checksum == request.POST.get('checksum'):
            # Save the file to the server
            # file_path = save_uploaded_file(uploaded_file)
            return JsonResponse({'success': 'File uploaded successfully'})
        else:
            return JsonResponse({'error': 'Checksum mismatch'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def owasp9_insecure(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user is not None:
            login(request, user)
            return HttpResponse("Logged in successfully.")
        else:
            return HttpResponse("Invalid login attempt.")
    else:
        return render(request, 'signin.html')

logger = logging.getLogger(__name__)
def owasp9_secure(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        ip_address = request.META.get('REMOTE_ADDR')
        attempt_time = now()

        user = authenticate(username=username, password=password)
        if user is not None:
            logger.warning(f"Successful login for user: {username}, IP: {ip_address}, Time: {attempt_time}")
            login(request, user)
            return HttpResponse("Logged in successfully.")
        else:
            logger.warning(f"Failed login attempt for username: {username}, IP: {ip_address}, Time: {attempt_time}")
            return HttpResponse("Invalid login attempt.")
    else:
        return render(request, 'signin.html')

def owasp10_insecure(request):
    try:
        # Get the URL of the external API from the request parameters
        api_url = request.GET.get('api_url')
        # return HttpResponse(api_url)
        response = requests.get("https://"+api_url)

        if response.status_code == 200:
            data = response.json()
            return JsonResponse(data)
        else:
            return JsonResponse({'error': 'Failed to fetch data from API'}, status=500)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

def owasp10_secure(request):
    try:
        # URL of the trusted external API
        api_url = 'https://swapi.dev/api/people/1/'
    
        response = requests.get(api_url)
        
        if response.status_code == 200:
            data = response.json()
            return JsonResponse(data)
        else:
            return JsonResponse({'error': 'Failed to fetch data from API'}, status=500)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)