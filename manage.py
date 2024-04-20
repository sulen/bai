#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from subprocess import run, PIPE

def run_safety_check():
    """Run safety check."""
    result = run(['safety', 'check', '--full-report'], stdout=PIPE, stderr=PIPE)
    if result.returncode != 0:
        print("Safety check failed. Exiting.")
        print(result.stdout.decode('utf-8', errors='ignore'))
        print(result.stderr.decode('utf-8', errors='ignore'))
        sys.exit(1)

def main():
    """Run administrative tasks."""
    # owasp6
    # run_safety_check()

    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'bai.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
