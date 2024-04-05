
# settings_insecure.py

# Włączony tryb debugowania w środowisku produkcyjnym, co może prowadzić do ujawnienia wrażliwych danych.
DEBUG = True

# Zbyt szeroka konfiguracja ALLOWED_HOSTS, która może pozwolić na ataki.
ALLOWED_HOSTS = ['*']

# Użycie domyślnego klucza tajnego, co jest niebezpieczne i może ułatwić ataki.
SECRET_KEY = 'django-insecure-+s3bo*v^6ez+74@%v^#y5#fyg&$^lgx)u4w^!f4)5^g7$d9w$l'

# Konfiguracja bazy danych bez hasła lub z domyślnymi poświadczeniami.
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.sqlite3',
    }
}

# Brak odpowiedniego middleware zapewniającego bezpieczeństwo.
MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    # Brakuje 'django.middleware.clickjacking.XFrameOptionsMiddleware'.
]
