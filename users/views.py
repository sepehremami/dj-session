from django.shortcuts import HttpResponse
from django.contrib.auth import authenticate, login
from django.contrib.auth import get_user_model

User = get_user_model()


def register(request):
    
    username_to_create = 'sepehr'
    if User.objects.filter(username=username_to_create).exists():
        return HttpResponse("User already exists")

    user = User(
        username=username_to_create,
        email='user@gmail.com'
    )
    user.set_password("1234")
    user.save()

    return HttpResponse("User created")


def login_view(request):
    if request.method == "GET":
        username = request.GET.get("username")
        password = request.GET.get("password")

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is not None:
            login(request, user)
            return HttpResponse("Logged in successfully")

        return HttpResponse("Invalid username or password")

    return HttpResponse("Send a POST request with username and password.")



def show_session(request):
    return HttpResponse(f'username: {request.user}')