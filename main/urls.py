from django.urls import path

from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path('signin/', views.signin, name='signin'),
    path("owasp1_insecure", views.owasp1_insecure, name="index"),
    path("owasp1_secure", views.owasp1_secure, name="index"),
    path("owasp2_insecure", views.change_password_insecure, name="change_password_insecure"),
    path("owasp2_secure", views.change_password_secure, name="change_password_secure"),

    path("owasp3_insecure", views.owasp3_insecure, name="index"),
    path("owasp3_secure", views.owasp3_secure, name="index"),
    #todo: 4
    # owasp 5 done in settings files
    # owasp 6 done in manage.py
    path("owasp7_insecure", views.owasp7_insecure, name="index"),
    path("owasp7_secure", views.owasp7_secure, name="index"),
    path("owasp8_insecure", views.owasp8_insecure, name="index"),
    path("owasp8_secure", views.owasp8_secure, name="index"),
    path("owasp9_insecure", views.owasp9_insecure, name="index"),
    path("owasp9_secure", views.owasp9_secure, name="index"),
    path("owasp10_insecure", views.owasp10_insecure, name="index"),
    path("owasp10_secure", views.owasp10_secure, name="index"),
]
