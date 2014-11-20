# Copyright (c) 2011-2014 Yin Yin
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
S3TempURL Middleware

Allows the creation of URLs to provide temporary access to objects.

"""

__all__ = ['TempURL', 'filter_factory',
           'DEFAULT_INCOMING_REMOVE_HEADERS',
           'DEFAULT_INCOMING_ALLOW_HEADERS',
           'DEFAULT_OUTGOING_REMOVE_HEADERS',
           'DEFAULT_OUTGOING_ALLOW_HEADERS']

import hmac
from hashlib import md5, sha1
from os.path import basename
from time import time
from urllib import urlencode
from urlparse import parse_qs

from swift.proxy.controllers.base import get_account_info
from swift.common.swob import HeaderKeyDict, HTTPUnauthorized
from swift.common.utils import split_path, get_valid_utf8_str, \
    register_swift_info, get_hmac, streq_const_time, quote

def get_s3_tempurl_keys_from_metadata(meta):
    """
    Extracts the tempurl keys from metadata.

    :param meta: account metadata
    :returns: list of keys found (possibly empty if no keys set)

    Example:
      meta = get_account_info(...)['meta']
      keys = get_s3_tempurl_keys_from_metadata(meta)
    """
    return [get_valid_utf8_str(value) for key, value in meta.iteritems()
            if key.lower() in ('s3-temp-url-key', 's3-temp-url-key-2')]


def disposition_format(filename):
    return '''attachment; filename="%s"; filename*=UTF-8''%s''' % (
        quote(filename, safe=' /'), quote(filename))


class S3TempURL(object):
    """
    WSGI Middleware to grant temporary URLs specific access to Swift
    resources. See the overview for more information.

    :param app: The next WSGI filter or app in the paste.deploy
                chain.
    :param conf: The configuration dict for the middleware.
    """

    def __init__(self, app, conf,
                 methods=('GET', 'HEAD', 'PUT', 'POST', 'DELETE')):
        #: The next WSGI application/filter in the paste.deploy pipeline.
        self.app = app
        #: The filter configuration dict.
        self.conf = conf

        #: The methods allowed with Temp URLs.
        self.methods = methods

        #: HTTP user agent to use for subrequests.
        self.agent = '%(orig)s TempURL'

    def __call__(self, env, start_response):
        """
        Main hook into the WSGI paste.deploy filter/app pipeline.

        :param env: The WSGI environment dict.
        :param start_response: The WSGI start_response hook.
        :returns: Response as per WSGI.
        """
        if env['REQUEST_METHOD'] == 'OPTIONS':
            return self.app(env, start_response)
        info = self._get_s3_temp_url_info(env)
        s3_temp_url_sig, s3_temp_url_expires = info
        s3_method, s3_expires, s3_path, s3_access_key, s3_sig = info
        if s3_sig is None and s3_expires is None:
            return self.app(env, start_response)
        if not s3_sig or not s3_expires:
            return self._invalid(env, start_response)
        account = self._get_account(env)
        if not account:
            return self._invalid(env, start_response)
        keys = self._get_keys(env, account)
        if not keys:
            return self._invalid(env, start_response)
        if env['REQUEST_METHOD'] == 'HEAD':
            s3_hmac_vals = (
                self._get_s3_hmacs(env, temp_url_expires, keys) +
                self._get_s3_hmacs(env, temp_url_expires, keys,
                                request_method='GET') +
                self._get_s3_hmacs(env, temp_url_expires, keys,
                                request_method='POST') +
                self._get_s3_hmacs(env, temp_url_expires, keys,
                                request_method='PUT'))
        else:
            s3_hmac_vals = self._get_s3_hmacs(env, temp_url_expires, keys)

        # While it's true that any() will short-circuit, this doesn't affect
        # the timing-attack resistance since the only way this will
        # short-circuit is when a valid signature is passed in.
        is_valid_hmac = any(streq_const_time(temp_url_sig, hmac)
                            for hmac in s3_hmac_vals)
        if not is_valid_hmac:
            return self._invalid(env, start_response)
        env['swift.authorize'] = lambda req: None
        env['swift.authorize_override'] = True
        env['REMOTE_USER'] = '.wsgi.s3tempurl'

        def _start_response(status, headers, exc_info=None):
            headers = self._clean_outgoing_headers(headers)
            if env['REQUEST_METHOD'] == 'GET' and status[0] == '2':
                # figure out the right value for content-disposition
                # 1) use the value from the query string
                # 2) use the value from the object metadata
                # 3) use the object name (default)
                out_headers = []
                existing_disposition = None
                for h, v in headers:
                    if h.lower() != 'content-disposition':
                        out_headers.append((h, v))
                    else:
                        existing_disposition = v
                # this is probably just paranoia, I couldn't actually get a
                # newline into existing_disposition
                value = disposition_value.replace('\n', '%0A')
                out_headers.append(('Content-Disposition', value))
                headers = out_headers
            return start_response(status, headers, exc_info)

        return self.app(env, _start_response)

    def _get_account(self, env):
        """
        Returns just the account for the request, if it's an object
        request and one of the configured methods; otherwise, None is
        returned.

        :param env: The WSGI environment for the request.
        :returns: Account str or None.
        """
        if env['REQUEST_METHOD'] in self.methods:
            try:
                ver, acc, cont, obj = split_path(env['PATH_INFO'], 4, 4, True)
            except ValueError:
                return None
            if ver == 'v1' and obj.strip('/'):
                return acc

    def _get_s3_temp_url_info(self, env):
        """
        Returns the provided temporary URL parameters (sig, expires),
        if given and syntactically valid. Either sig or expires could
        be None if not provided. If provided, expires is also
        converted to an int if possible or 0 if not, and checked for
        expiration (returns 0 if expired).

        :param env: The WSGI environment for the request.
        :returns: (method, expires, path, access_key, sig) as described above.
        """
        s3_method = s3_expires = s3_path = s3_access_key = s3_sig = None
        s3_path = env['RAW_PATH_INFO']
        s3_method = env['REQUEST_METHOD']
        qs = parse_qs(env.get('QUERY_STRING', ''), keep_blank_values=True)
        if 'Signature' in qs:
            s3_sig = qs['Signature'][0]
        if 'Expires' in qs:
            try:
                s3_expires = int(qs['Expires'][0])
            except ValueError:
                s3_expires = 0
            if s3_expires < time():
                s3_expires = 0
        if 'AWSAccessKeyId' in qs:
            s3_access_key = qs['AWSAccessKeyId'][0]

        return s3_method, s3_expires, s3_path, s3_access_key, s3_sig
        
    def _get_keys(self, env, account):
        """
        Returns the X-Account-Meta-Temp-URL-Key[-2] header values for the
        account, or an empty list if none is set.

        Returns 0, 1, or 2 elements depending on how many keys are set
        in the account's metadata.

        :param env: The WSGI environment for the request.
        :param account: Account str.
        :returns: [X-Account-Meta-Temp-URL-Key str value if set,
                   X-Account-Meta-Temp-URL-Key-2 str value if set]
        """
        account_info = get_account_info(env, self.app, swift_source='TU')
        return get_tempurl_keys_from_metadata(account_info['meta'])

    def _get_s3_hmacs(self, key, s3_method, s3_expires, s3_path):
        """
        """
        c_string = "%s\n\n\n%s\n%s" % (s3_method, s3_expires, s3_path)
        
        return hmac.new(key, c_string, sha1).hexdigest()

    def _invalid(self, env, start_response):
        """
        Performs the necessary steps to indicate a WSGI 401
        Unauthorized response to the request.

        :param env: The WSGI environment for the request.
        :param start_response: The WSGI start_response hook.
        :returns: 401 response as per WSGI.
        """
        if env['REQUEST_METHOD'] == 'HEAD':
            body = None
        else:
            body = '401 Unauthorized: Temp URL invalid\n'
        return HTTPUnauthorized(body=body)(env, start_response)

def filter_factory(global_conf, **local_conf):
    """Returns the WSGI filter for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    methods = conf.get('methods', 'GET HEAD PUT POST DELETE').split()
    register_swift_info('s3tempurl', methods=methods)

    return lambda app: TempURL(app, conf, methods=methods)
