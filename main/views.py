import logging

from django.contrib.auth.models import User
from django.db import connection
from django.shortcuts import get_object_or_404
from django.utils.timezone import now
from django_ratelimit.decorators import ratelimit


def index(request):
    return HttpResponse("Hello, world")


from django.contrib.auth import authenticate, login
from django.http import HttpResponse
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
            login(request, user)
            logger.info(f"Successful login for user: {username}, IP: {ip_address}, Time: {attempt_time}")
            return HttpResponse("Logged in successfully.")
        else:
            logger.warning(f"Failed login attempt for username: {username}, IP: {ip_address}, Time: {attempt_time}")
            return HttpResponse("Invalid login attempt.")
    else:
        return render(request, 'signin.html')
