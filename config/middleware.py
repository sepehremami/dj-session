from django.contrib.auth import get_user_model
from urllib.parse import urlsplit
from django.contrib import auth
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject
from django.contrib.sessions.backends.db import SessionStore
from django.conf import settings

def get_user(request):
    if not hasattr(request, "_cached_user"):
        request._cached_user = auth.get_user(request)
    return request._cached_user


class AuthenticationMiddleware(MiddlewareMixin):
    
    def process_request(self, request):
        
        # Load session from cookie
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        request.session = SessionStore(session_key=session_key)
        request.user = SimpleLazyObject(lambda: get_user(request))
        
        if hasattr(request, 'user') and request.user.is_authenticated:
            user = request.user
            
            session = SessionStore()
            session.clear()
            session.cycle_key()
            session[auth.SESSION_KEY] = str(user.pk)
            session[auth.BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
            session[auth.HASH_SESSION_KEY] = user.get_session_auth_hash()
            session.save()
            
            # connect session to current request
            request.session = session           
            
            request._forced_session_key = session.session_key       

    def process_response(self, request, response):
        # convert key to coockie
        if hasattr(request, '_forced_session_key'):
            response.set_cookie(
                settings.SESSION_COOKIE_NAME,
                request._forced_session_key,
                max_age=settings.SESSION_COOKIE_AGE,
                httponly=settings.SESSION_COOKIE_HTTPONLY,
                secure=settings.SESSION_COOKIE_SECURE,
            )
        return response