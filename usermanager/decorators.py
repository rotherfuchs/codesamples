import base64
import json

from models import AuditTrail, send_audit_trail

from django.http import HttpResponse
from django.contrib.auth import authenticate, login
from django.utils.translation import ugettext_lazy as _
from django.core.urlresolvers import reverse_lazy


def view_or_basicauth(view, request, test_func, realm="", prefix='', *args, **kwargs):
    """
    This is a helper function used by both 'logged_in_or_basicauth' and
    'has_perm_or_basicauth' that does the nitty of determining if they
    are already logged in or if they have provided proper http-authorization
    and returning the view if all goes well, otherwise responding with a 401.
    """
    if test_func(request.user):
        return view(request, *args, **kwargs)

    if 'HTTP_AUTHORIZATION' in request.META:
        auth = request.META['HTTP_AUTHORIZATION'].split()

        if len(auth) == 2:
            # NOTE: We are only support basic authentication for now.
            #
            if auth[0].lower() == "basic":
                uname, passwd = base64.b64decode(auth[1]).split(':')
                user = authenticate(username=uname, password=passwd)
                if user is not None:
                    if user.is_active:
                        login(request, user)
                        request.user = user

                        soap_action = request.META.get('HTTP_SOAPACTION')
                        if soap_action:
                            perm = prefix + '.' + json.loads(request.META.get('HTTP_SOAPACTION'))
                            if user.has_perm(perm):
                                return view(request, *args, **kwargs)
                            else:
                                send_audit_trail(
                                    request.user,
                                    _(u'ILLEGAL attempt to SOAP Interface %(method_name)s at %(path)s') % ({'method_name': soap_action, 'path': request.environ['PATH_INFO']}),
                                    AuditTrail.LEVEL_WARNING
                                )
                        # Just grabbing the WSDL
                        else:
                            return view(request, *args, **kwargs)

    # Either they did not provide an authorization header or
    # something in the authorization attempt failed. Send a 401
    # back to them to ask them to authenticate.
    #
    response = HttpResponse()
    response.status_code = 401
    response['WWW-Authenticate'] = 'Basic realm="%s"' % realm
    return response


def has_perm_or_basicauth(prefix='', realm=""):
    """
    Use:

    @logged_in_or_basicauth('asforums.view_forumcollection')
    def your_view:
        ...

    """
    def view_decorator(func):
        def wrapper(request, *args, **kwargs):
            return view_or_basicauth(func, request,
                                     lambda u: u.is_authenticated(),
                                     realm, prefix, *args, **kwargs)
        return wrapper
    return view_decorator


from django.http import HttpResponseRedirect


class AnonymousRequired(object):
    """A decorator that verifies if the current user is anonymous.
    Requests using this decorator are redirected to the given `redirect_to`
    URL on negative response.
    Implemented by the respective function below.

    """
    def __init__(self, view_function, redirect_to):
        self.view_function = view_function
        self.redirect_to = redirect_to

    def __call__(self, request, *args, **kwargs):
        if request.user is not None and request.user.is_authenticated():
            return HttpResponseRedirect(self.redirect_to)
        return self.view_function(request, *args, **kwargs)


def anonymous_required(view_function, redirect_to='/'):
    """Decorator Function, called if a page requires vistor being anonymous.

    @param view_function: the View calling this decorator
    @type view_function: dict

    @param redirect_to: a URL, to which the decorator shall redirect.
    @type redirect_to: string

    @return: A Django HTTP Response - either back to origin or to target.

    """
    return AnonymousRequired(view_function, redirect_to)


class LoginRequired(object):
    """A decorator that verifies if the current user is logged in.
    Requests using this decorator are redirected to the login URL on negative
    response.
    Implemented by the respective function below.

    """
    def __init__(self, view_function, redirect_to):
        self.view_function = view_function
        self.redirect_to = redirect_to

    def __call__(self, request, *args, **kwargs):
        if request.user is None or not request.user.is_authenticated():
            return HttpResponseRedirect(self.redirect_to)
        return self.view_function(request, *args, **kwargs)


def login_required(view_function, redirect_to=reverse_lazy('usermanager:login_user')):
    """Decorator Function, called if a page requires vistor being logged in.

    @param view_function: the View calling this decorator
    @type view_function: dict

    @param redirect_to: a URL, to which the decorator shall redirect.
    @type redirect_to: string

    @return: A Django HTTP Response - either back to origin or to target.

    """
    return LoginRequired(view_function, redirect_to)
