import webob.dec
import webob.exc

AUTH_CONTEXT_ENV = 'KEYSTONE_AUTH_CONTEXT'
AUTH_ADMIN_ROLE = 'admin'
IP_ADDR_HEADER = 'REMOTE_ADDR'
WHITELIST_IP_PATH = '/etc/keystone/ip_list.txt'

def load_whitelisted_ips():
    with open(WHITELIST_IP_PATH, 'r') as f:
        return f.read().splitlines()

class RestrictionWsgiMiddleware(object):
    """WSGI Middleware whitelisting ip addresses for admin roles."""

    def __init__(self, application):
        """Initialize middleware with api-paste.ini arguments.

        :application: wsgi app
        """
        self.application = application
        self.name = "wsgi"
        self.ip_list = load_whitelisted_ips()

    @classmethod
    def factory(cls, global_conf, **local_conf):
        def filter_(app):
            return cls(app, **local_conf)
        return filter_

    @webob.dec.wsgify
    def __call__(self, request):

        auth_context = request.environ.get(AUTH_CONTEXT_ENV, {})
        if 'roles' in auth_context and AUTH_ADMIN_ROLE in auth_context['roles']:
            remote_addr = request.environ.get(IP_ADDR_HEADER, None)
            if remote_addr not in self.ip_list:
                return webob.exc.HTTPForbidden()
        return request.get_response(self.application)
