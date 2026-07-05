from django.contrib.auth import get_user_model
from django.contrib.auth.models import AnonymousUser
from django.test import RequestFactory, TestCase
from django.http import HttpResponse
from django.conf import settings
from django.contrib.sessions.backends.db import SessionStore
from django.contrib.auth import SESSION_KEY, BACKEND_SESSION_KEY, HASH_SESSION_KEY
from config.middleware import AuthenticationMiddleware

User = get_user_model()


class SessionAndAuthenticationMiddlewareTests(TestCase):
    
    def get_response(self, request):
        """Helper to simulate a standard view response."""
        return HttpResponse("OK")

    def test_loads_empty_session_if_no_cookie(self):
        """
        Tests that if no cookie is sent, the middleware initializes an empty session
        and sets the request.user as an AnonymousUser.
        """
        middleware = AuthenticationMiddleware(self.get_response)
        request = RequestFactory().get("/")
        request.COOKIES = {}

        # Run process_request manually
        middleware.process_request(request)

        # Verify session is initialized but has no key yet (since it's not saved)
        self.assertTrue(hasattr(request, 'session'))
        self.assertIsNone(request.session.session_key)
        
        # Verify the user is set to AnonymousUser
        self.assertTrue(hasattr(request, "user"))
        self.assertIsInstance(request.user, AnonymousUser)
        self.assertFalse(request.user.is_authenticated)

    def test_reuses_existing_session_from_cookie(self):
        """
        Tests that the middleware successfully reconstructs an existing session 
        from the cookie value.
        """
        # Create and save a manual session first
        session = SessionStore()
        session.save()

        middleware = AuthenticationMiddleware(self.get_response)
        request = RequestFactory().get("/")
        request.COOKIES = {
            settings.SESSION_COOKIE_NAME: session.session_key,
        }

        # Run process_request
        middleware.process_request(request)

        # Verify the middleware successfully reloaded the same session key
        self.assertEqual(
            request.session.session_key,
            session.session_key,
        )

    def test_session_persists_data_across_requests(self):
        """
        Tests that modified session data actually saves and persists across requests.
        """
        # Create an initial session
        session = SessionStore()
        session["foo"] = "bar"
        session.save()

        middleware = AuthenticationMiddleware(self.get_response)
        
        # First request (simulating reading the session)
        request1 = RequestFactory().get("/")
        request1.COOKIES = {settings.SESSION_COOKIE_NAME: session.session_key}
        middleware.process_request(request1)

        self.assertEqual(request1.session["foo"], "bar")

        # Modify session data
        request1.session["foo"] = "updated_bar"
        request1.session.save()

        # Second request (verifying the data was persisted)
        request2 = RequestFactory().get("/")
        request2.COOKIES = {settings.SESSION_COOKIE_NAME: session.session_key}
        middleware.process_request(request2)

        self.assertEqual(request2.session["foo"], "updated_bar")


class AuthenticationIntegrationTests(TestCase):

    def test_authenticated_user_loaded_from_session_successfully(self):
        """
        Integration test: Verifies that an authenticated user's ID stored in 
        the session is successfully resolved into a real User instance on the request.
        """
        # Create a test user in the database
        user = User.objects.create_user(
            username="alice",
            password="secret",
        )

        # Manually seed the session backend with Django's auth keys
        session = SessionStore()
        session[SESSION_KEY] = str(user.pk)
        session[BACKEND_SESSION_KEY] = 'django.contrib.auth.backends.ModelBackend'
        session[HASH_SESSION_KEY] = user.get_session_auth_hash()
        session.save()

        middleware = AuthenticationMiddleware(lambda r: HttpResponse("OK"))
        
        # Simulate a request hitting the server with the valid session cookie
        request = RequestFactory().get("/")
        request.COOKIES = {
            settings.SESSION_COOKIE_NAME: session.session_key,
        }

        # Process the request through our middleware logic
        middleware.process_request(request)

        # Assertions to prove custom manual authentication works!
        self.assertTrue(request.user.is_authenticated)
        self.assertEqual(request.user.pk, user.pk)
        self.assertEqual(request.user.username, "alice")

    def test_login_flow_sets_cookie_in_process_response(self):
        """
        Tests the post-login behavior: when a view sets `request._authenticated_user`,
        `process_response` must create a session and set the response cookie.
        """
        user = User.objects.create_user(username="bob", password="password123")
        
        middleware = AuthenticationMiddleware(lambda r: HttpResponse("OK"))
        request = RequestFactory().get("/login/")
        response = HttpResponse("Logged in successfully")
        
        # Simulate what the views.login_view does upon successful credential validation
        request._authenticated_user = user
        
        # Run process_response manually
        updated_response = middleware.process_response(request, response)
        
        # Verify the cookie is injected into the HTTP response headers
        self.assertIn(settings.SESSION_COOKIE_NAME, updated_response.cookies)
        
        # Extract the created session key from the cookie header
        session_key = updated_response.cookies[settings.SESSION_COOKIE_NAME].value
        
        # Verify the session is actually persisted in the DB and tied to Bob
        session_in_db = SessionStore(session_key=session_key)
        self.assertEqual(session_in_db[SESSION_KEY], str(user.pk))