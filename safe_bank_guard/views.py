from django.http import HttpResponse

def home(request):
    return HttpResponse("Welcome! Your server is running inside Docker.")
