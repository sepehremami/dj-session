from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from urllib.parse import urlsplit
from django.contrib import auth
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject
from django.contrib.sessions.backends.db import SessionStore
from django.conf import settings

def get_user(request):
    if not hasattr(request, "_cached_user"):
        if hasattr(request, 'session') and auth.SESSION_KEY in request.session:
            user_id = request.session[auth.SESSION_KEY]
            User = get_user_model()
            try:
                request._cached_user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                request._cached_user = AnonymousUser()
        else:
            request._cached_user = AnonymousUser()
    return request._cached_user


class AuthenticationMiddleware(MiddlewareMixin):
    
    def process_request(self, request):
        
        # Load session from cookie
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        request.session = SessionStore(session_key=session_key)
        
        request.user = SimpleLazyObject(lambda: get_user(request))
           

    def process_response(self, request, response):
        
        if hasattr(request, '_authenticated_user'):
            
            user = request._authenticated_user 
            
            session = SessionStore()
            session.clear()
            session.cycle_key()
            session[auth.SESSION_KEY] = str(user.pk)
            session[auth.BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
            session[auth.HASH_SESSION_KEY] = user.get_session_auth_hash()
            session.save()
            
            # connect session to current request
            request.session = session 
            
        
            response.set_cookie(
                settings.SESSION_COOKIE_NAME,
                session.session_key,
                max_age=settings.SESSION_COOKIE_AGE,
                httponly=settings.SESSION_COOKIE_HTTPONLY,
                secure=settings.SESSION_COOKIE_SECURE,
            )
        return response