
# settings_secure.py

# Wyłączenie trybu debugowania w środowisku produkcyjnym.
DEBUG = False

# Ograniczenie ALLOWED_HOSTS do konkretnego hosta zapobiega niektórym atakom

ALLOWED_HOSTS = ['yourdomain.com']

# Użycie silnego, unikalnego klucza tajnego.
SECRET_KEY = 'generate a strong secret key'

# Bezpieczna konfiguracja bazy danych z silnym hasłem.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'your_db_name',
        'USER': 'your_db_user',
        'PASSWORD': 'your_db_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}

# Kompletny zestaw middleware zapewniający bezpieczeństwo, w tym ochronę przed clickjackingiem.
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]
