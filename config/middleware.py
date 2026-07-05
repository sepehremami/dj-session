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
        
        User = get_user_model()
        
        try:
            user = User.objects.get(pk=1)
        except User.DoesNotExist:
            user = None
        
        if user:
            session = SessionStore()
            session.clear()
            session.cycle_key()
            
            session[auth.SESSION_KEY] = str(user.pk)
            session[auth.BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
            session[auth.HASH_SESSION_KEY] = user.get_session_auth_hash()
            session.save()

            # connect session to current request
            request.session = session           
            
            # making the browser to identify other requests of this session
            # we have to set it's key in the response
            request._forced_session_key = session.session_key       
            
        request.user = SimpleLazyObject(lambda: get_user(request))
        
    
    def process_response(self, request, response):
        if hasattr(request, '_forced_session_key'):
            response._set_cookie(
                settings.SESSION_COOKIE_NAME,
                request._forced_session_key,
                max_age=settings.SESSION_COOKIE_AGE,
                path=settings.SESSION_COOKIE_PATH,
                domain=settings.SESSION_COOKIE_DOMAIN,
                secure=settings.SESSION_COOKIE_SECURE,
                httponly=settings.SESSION_COOKIE_HTTPONLY,
            )
        
        return response