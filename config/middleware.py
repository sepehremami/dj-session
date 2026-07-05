from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
#from urllib.parse import urlsplit
from django.contrib import auth
from django.utils.deprecation import MiddlewareMixin
from django.utils.functional import SimpleLazyObject
from django.contrib.sessions.backends.db import SessionStore
from django.conf import settings

def get_user(request):
    """
    Helper function to manually retrieve the user from the database session.
    It returns either a fully populated User instance or an AnonymousUser instance.
    """
    # Check if the user has already been fetched and cached for this request lifecycle
    if not hasattr(request, "_cached_user"):
        
        # Check if the session exists and contains Django's standard authentication key
        if hasattr(request, 'session') and auth.SESSION_KEY in request.session:
            user_id = request.session[auth.SESSION_KEY]
            User = get_user_model()
            try:
                # Attempt to retrieve the authenticated user from the database
                request._cached_user = User.objects.get(pk=user_id)
            except User.DoesNotExist:
                # Fallback to AnonymousUser if the user ID no longer exists in the DB
                request._cached_user = AnonymousUser()
        else:
            # Fallback to AnonymousUser if no active session or auth key is found
            request._cached_user = AnonymousUser()
    return request._cached_user


class AuthenticationMiddleware(MiddlewareMixin):
    """
    Custom middleware designed to handle session management and user authentication 
    completely manually, bypassing Django's default built-in session middleware.
    """
    def process_request(self, request):
        """
        Executed on the incoming request path (before reaching the view).
        """
        # 1. Load session from cookie | Extract the session key sent by the client's browser cookies
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        
        # 2. Manually reconstruct the Session object from the database using the session key
        request.session = SessionStore(session_key=session_key)
        
        # 3. Lazily attach the user object to the request to optimize DB hits
        request.user = SimpleLazyObject(lambda: get_user(request))
           

    def process_response(self, request, response):
        """
        Executed on the outgoing response path (after the view has finished executing).
        """
        
        # 1. Check if the login view successfully authenticated a user and flagged the request
        if hasattr(request, '_authenticated_user'):
            user = request._authenticated_user 
            
            # 2. Instantiate a fresh, clean session in the database backend
            session = SessionStore()
            session.clear()
            session.cycle_key() # Generate a secure, randomized session key
            
            # 3. Manually populate the session dictionary mimicking Django's native login behavior
            session[auth.SESSION_KEY] = str(user.pk) # Store the user ID
            session[auth.BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend' # Define auth backend path
            session[auth.HASH_SESSION_KEY] = user.get_session_auth_hash() # Store password hash to invalidate on password changes
            session.save() # Persist the session row inside the `django_session` table
            
            # 4. Attach the newly created session to the current request context
            request.session = session 
            
            # 5. Set the session cookie explicitly on the HTTP response object heading back to the client
            response.set_cookie(
                settings.SESSION_COOKIE_NAME,
                session.session_key,    # Send the actual raw database session key string
                max_age=settings.SESSION_COOKIE_AGE,    # Cookie TTL settings
                httponly=settings.SESSION_COOKIE_HTTPONLY,  # Mitigate XSS attacks by blocking JS access to the cookie
                secure=settings.SESSION_COOKIE_SECURE,  # Ensure cookie is only transmitted over HTTPS connections
            )
        return response