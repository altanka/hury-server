from typing import cast
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse

from users.models import User

import json
import re
import os

import firebase_admin

config = {
        "type": os.environ.get('FIREBASE_TYPE'),
        "project_id": os.environ.get('FIREBASE_PROJECT_ID'),
        "private_key_id": os.environ.get('FIREBASE_PRIVATE_KEY_ID'),
        "private_key": os.environ.get('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
        "client_email": os.environ.get('FIREBASE_CLIENT_EMAIL'),
        "client_id": os.environ.get('FIREBASE_CLIENT_ID'),
        "auth_uri": os.environ.get('FIREBASE_AUTH_URI'),
        "token_uri": os.environ.get('FIREBASE_TOKEN_URI'),
        "auth_provider_x509_cert_url": os.environ.get('FIREBASE_AUTH_PROVIDER_X509_CERT_URL'),
        "client_x509_cert_url": os.environ.get('FIREBASE_CLIENT_X509_CERT_URL'),
}

cred = firebase_admin.credentials.Certificate(config)
    
default_app = firebase_admin.initialize_app(cred)


def Firebase_validation(id_token):
   """
   This function receives id token sent by Firebase and
   validate the id token then check if the user exist on
   Firebase or not if exist it returns True else False
   """
   try:
       decoded_token = firebase_admin.auth.verify_id_token(id_token)
       uid = decoded_token['uid']
       provider = decoded_token['firebase']['sign_in_provider']
       image = None
       name = None
       if "name" in decoded_token:
           name = decoded_token['name']
       if "picture" in decoded_token:
           image = decoded_token['picture']
       try:
           user = firebase_admin.auth.get_user(uid)
           email = user.email
           if user:
               return {
                   "status": True,
                   "uid": uid,
                   "email": email,
                   "name": name,
                   "provider": provider,
                   "image": image
               }
           else:
               return False
       except firebase_admin.UserNotFoundError:
           print("user not exist")
   except firebase_admin.ExpiredIdTokenError:
       print("invalid token")


def login(request):
    req_dict = json.loads(request.body)
    email = req_dict["email"]
    id_token = req_dict["id_token"]

    response_data = {}
    
    try:
        user = User.objects.get(email=email)
        if user.id_token == id_token:
            response_data["valid"] = True
            response_data["message"] = "Logged in"
        else:
            response_data["valid"] = False
            response_data["message"] = "Id token is not valid"
    except User.DoesNotExist:
        response_data["valid"] = False
        response_data["message"] = "Email does not found"

    return JsonResponse(response_data)


def register(request):
    
    req_dict = json.loads(request.body)
    email = req_dict["email"]
    id_token = req_dict["id_token"]

    response_data = {}

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        response_data["successful"] = False
        response_data["message"] = "Please check your email"
    else:
        try:
            json.loads(id_token)
            user = User.objects.get(email=email)
            response_data["successful"] = False
            response_data["message"] = "A user is registered with %s" % user.email
        except User.DoesNotExist:
            response_data["successful"] = True
            response_data["message"] = "Registration is successful"
            if Firebase_validation(id_token):
                user = User(email=email, id_token=id_token)
                user.save()
            else:
                raise ValueError()
        except (ValueError, TypeError):
            response_data["successful"] = False
            response_data["message"] = "Please check your token"
    
    return JsonResponse(response_data)
