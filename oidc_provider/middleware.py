try:
    # https://docs.djangoproject.com/en/1.10/topics/http/middleware/#upgrading-pre-django-1-10-style-middleware
    from django.utils.deprecation import MiddlewareMixin
except ImportError:
    MiddlewareMixin = object

from oidc_provider import settings
from oidc_provider.lib.utils.common import get_browser_state_or_default


class SessionManagementMiddleware(MiddlewareMixin):
    """
    Maintain a `op_browser_state` cookie along with the `sessionid` cookie that
    represents the End-User's login state at the OP. If the user is not logged
    in then use the value of settings.OIDC_UNAUTHENTICATED_SESSION_MANAGEMENT_KEY.
    """

    def process_response(self, request, response):
        if settings.get('OIDC_SESSION_MANAGEMENT_ENABLE'):
            response.set_cookie('op_browser_state', get_browser_state_or_default(request))
        return response


class OpenIDAuthenticationMiddleware:
    """Middleware class for openid connect user authentication."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        assert hasattr(request, 'session'), (
            "The Django authentication middleware requires session middleware "
            "to be installed. Edit your MIDDLEWARE setting to insert "
            "'django.contrib.sessions.middleware.SessionMiddleware' before "
            "'django.contrib.auth.middleware.AuthenticationMiddleware'."
        )
        request.oidc_user = settings.get("OIDC_GET_USER_HOOK", import_str=True)(request)
        response = self.get_response(request)
        return response
