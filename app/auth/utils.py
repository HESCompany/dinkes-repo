from flask import current_app

def check_registration_secret_key(secret_key):
    return secret_key == current_app.config['REGISTRATION_SECRET_KEY']
