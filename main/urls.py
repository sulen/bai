from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('signin/', views.signin, name='signin'),
    path("owasp1_insecure", views.owasp1_insecure, name="index"),
    path("owasp1_secure", views.owasp1_secure, name="index"),
    #todo: 2
    path("owasp3_insecure", views.owasp3_insecure, name="index"),
    path("owasp3_secure", views.owasp3_secure, name="index"),
    #todo: 4
    # owasp 5 done in settings files
    #todo: 6
    path("owasp7_insecure", views.owasp7_insecure, name="index"),
    path("owasp7_secure", views.owasp7_secure, name="index"),
    #todo: 8
    path("owasp9_insecure", views.owasp9_insecure, name="index"),
    path("owasp9_secure", views.owasp9_secure, name="index"),
    #todo: 10
]
