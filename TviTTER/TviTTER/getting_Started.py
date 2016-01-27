import os
import warnings
import re

import requests
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth1, OAuth2

try:   from StringIO import StringIO
except ImportError:from io import StringIO

try:  import simplejson as json
except ImportError: import json

from urllib import urlencode, quote_plus
from urlparse import parse_qsl

numeric_types = (int, long, float)

TWITTER_HTTP_STATUS_CODE = {
    200: ('OK', 'Success!'),
    304: ('Not Modified', 'There was no new data to return.'),
    400: ('Bad Request', 'The request was invalid. An accompanying \
          error message will explain why. This is the status code \
          will be returned during rate limiting.'),
    401: ('Unauthorized', 'Authentication credentials were missing \
          or incorrect.'),
    403: ('Forbidden', 'The request is understood, but it has been \
          refused. An accompanying error message will explain why. \
          This code is used when requests are being denied due to \
          update limits.'),
    404: ('Not Found', 'The URI requested is invalid or the resource \
          requested, such as a user, does not exists.'),
    406: ('Not Acceptable', 'Returned by the Search API when an \
          invalid format is specified in the request.'),
    410: ('Gone', 'This resource is gone. Used to indicate that an \
          API endpoint has been turned off.'),
    422: ('Unprocessable Entity', 'Returned when an image uploaded to \
          POST account/update_profile_banner is unable to be processed.'),
    429: ('Too Many Requests', 'Returned in API v1.1 when a request cannot \
          be served due to the application\'s rate limit having been \
          exhausted for the resource.'),
    500: ('Internal Server Error', 'Something is broken. Please post to the \
          group so the Twitter team can investigate.'),
    502: ('Bad Gateway', 'Twitter is down or being upgraded.'),
    503: ('Service Unavailable', 'The Twitter servers are up, but overloaded \
          with requests. Try again later.'),
    504: ('Gateway Timeout', 'The Twitter servers are up, but the request \
          couldn\'t be serviced due to some failure within our stack. Try \
          again later.'),
}

class TviTTERError(Exception):
    def __init__(self, msg, error_code=None, retry_after=None):
        self.error_code = error_code

        if error_code is not None and error_code in TWITTER_HTTP_STATUS_CODE:
            msg = 'Twitter API returned a %s (%s), %s' % \
                  (error_code, TWITTER_HTTP_STATUS_CODE[error_code][0],msg)
                   
        super(TviTTERError, self).__init__(msg)

#    @property
#    def msg(self):  # pragma: no cover
#        return self.args[0]


class StatusMixin(object):

    def update_status(self, **params):
        """Updates the authenticating user's current status, also known as tweeting

        Docs: https://dev.twitter.com/docs/api/1.1/post/statuses/update

        """
        return self.post('statuses/update', params=params)


class VideoMixin(object) : 
    def upload_video(self, media, media_type, size=None, chunk_size=512*1024):
    
        """Uploads video file to Twitter servers in chunks. 
        The video is uploaded in chunks of  chunk_size. chunk_size can be provide as parameter. By default, chunk_size is 512KN

        * The upload starts with INIT, segment_index = 0, it returns media_id of the upload in progress
        * for every segment that we send next, we send command : APPEND, media_id = media_id (that was returned 
          in the previous step), segment_index = increase this by one on every step
        * continue step 2 till there is data to be sent to the server (Twitter)
        * complete the upload by sending the command "FINALIZE" and the media_id

        """
        upload_url = 'https://upload.twitter.com/1.1/media/upload.json'

        #find the size of file 
        if not size:
            media.seek(0, os.SEEK_END)
            size = media.tell()
            media.seek(0)

        # Stage 1: Initialize the request. The video upload process starts from here
        params = {
            'command': 'INIT',
            'media_type': media_type,
            'total_bytes': size
        }
        response_init = self.post(upload_url, params=params)
        media_id = response_init['media_id']

        # Stage 2: If there is data to be sent to the twitter server, APPEND the call with media chunks of size 512kb
        segment_index = 0
        while True:
            data = media.read(1*chunk_size)   #default chunk size  = 512kb
            if not data:
                break
            media_chunk = StringIO()
            media_chunk.write(data)
            media_chunk.seek(0)

            params = {
                'command': 'APPEND',
                'media_id': media_id,
                'segment_index': segment_index,
                'media': media_chunk,
            }
            self.post(upload_url, params=params)
            segment_index += 1

        # Stage 3: FINALIZE call to complete upload
        params = {
            'command': 'FINALIZE',
            'media_id': media_id
        }
        return self.post(upload_url, params=params)



def _transparent_params(_params):
    params = {}
    files = {}
    for k, v in _params.items():
        print "k = ",k, " v = ",v
        if hasattr(v, 'read') and callable(v.read):
            files[k] = v  # pragma: no cover
        elif isinstance(v, bool):
            if v:
                params[k] = 'true'
            else:
                params[k] = 'false'
        elif isinstance(v, basestring) or isinstance(v, numeric_types):
            params[k] = v
        elif isinstance(v, list):
            try:
                params[k] = ','.join(v)
            except TypeError:
                params[k] = ','.join(map(str, v))
        else:
            continue  # pragma: no cover
    print "params = ",params
    print "files = ",files
    return params, files

class TviTTER(VideoMixin, StatusMixin, object):
    def __init__(self, app_key=None, app_secret=None, oauth_token=None,
                 oauth_token_secret=None, access_token=None,
                 token_type='bearer', oauth_version=1, api_version='1.1',
                 client_args=None, auth_endpoint='authenticate'):
        """Instantiates an instance of Twython. Takes optional parameters for
        authentication and such (see below).
        
        Parameters : 
            Optional parameters :
                app_key: (optional) Your applications key
                app_secret: (optional) Your applications secret key
                oauth_token: (optional) When using **OAuth 1**, combined with
                    oauth_token_secret to make authenticated calls
                oauth_token_secret: (optional) When using **OAuth 1** combined
                        with oauth_token to make authenticated calls
                access_token: (optional) When using **OAuth 2**, provide a
                        valid access token if you have one
                token_type: (optional) When using **OAuth 2**, provide your
                    token type. Default: bearer
                oauth_version: (optional) Choose which OAuth version to use. Default: 1
                api_version: (optional) Choose which Twitter API version to use. Default: 1.1
                client_args: (optional) Accepts some requests Session parameters
                    and some requests Request parameters.
              
                auth_endpoint: (optional) Lets you select which authentication endpoint will use your application.
                Default: authenticate.
        """

        # API urls, OAuth urls and API version; needed for hitting that there
        # API.
        self.api_version = api_version
        self.api_url = 'https://api.twitter.com/%s'

        self.app_key = app_key
        self.app_secret = app_secret
        self.oauth_token = oauth_token
        self.oauth_token_secret = oauth_token_secret
        self.access_token = access_token

        # OAuth 1
        self.request_token_url = self.api_url % 'oauth/request_token'
        self.access_token_url = self.api_url % 'oauth/access_token'
        self.authenticate_url = self.api_url % ('oauth/%s' % auth_endpoint)

        if self.access_token:  # If they pass an access token, force OAuth 2
            oauth_version = 2

        self.oauth_version = oauth_version

        # OAuth 2
        if oauth_version == 2:
            self.request_token_url = self.api_url % 'oauth2/token'

        self.client_args = client_args or {}
        default_headers = {'User-Agent': 'fueled development 1.0'}
        if 'headers' not in self.client_args:
            # If they didn't set any headers, set our defaults for them
            self.client_args['headers'] = default_headers
        elif 'User-Agent' not in self.client_args['headers']:
            # If they set headers, but didn't include User-Agent.. set
            # it for them
            self.client_args['headers'].update(default_headers)

        # Generate OAuth authentication object for the request
        # If no keys/tokens are passed to __init__, auth=None allows for
        # unauthenticated requests, although I think all v1.1 requests
        # need auth
        auth = None
        print "oauth_version = ", oauth_version
        if oauth_version == 1:
            # User Authentication is through OAuth 1
            print "oauth_version = ", oauth_version
            if self.app_key is not None and self.app_secret is not None:
                auth = OAuth1(self.app_key, self.app_secret,
                                self.oauth_token, self.oauth_token_secret)

        elif oauth_version == 2 and self.access_token:
            # Application Authentication is through OAuth 2
            token = {'token_type': token_type,
                     'access_token': self.access_token}
            auth = OAuth2(self.app_key, token=token)

        self.client = requests.Session()
        self.client.auth = auth

        # Make a copy of the client args and iterate over them
        # Pop out all the acceptable args at this point because they will
        # Never be used again.
        client_args_copy = self.client_args.copy()
        for k, v in client_args_copy.items():
            if k in ('cert', 'hooks', 'max_redirects', 'proxies'):
                setattr(self.client, k, v)
                self.client_args.pop(k)  # Pop, pop!

        # Headers are always present, so we unconditionally pop them and merge
        # them into the session headers.
        self.client.headers.update(self.client_args.pop('headers'))

        self._last_call = None

#    def __repr__(self):
#        return '<Twython: %s>' % (self.app_key)

    def _request(self, url, method='GET', params=None, api_call=None):
        """Internal request method"""
        method = method.lower()
        params = params or {}

        func = getattr(self.client, method)
        params, files = _transparent_params(params)

        requests_args = {}
        for k, v in self.client_args.items():
            # Maybe this should be set as a class variable and only done once?
            if k in ('timeout', 'allow_redirects', 'stream', 'verify'):
                requests_args[k] = v

        if method == 'get':
            requests_args['params'] = params
        else:
            requests_args.update({
                'data': params,
                'files': files,
            })
        try:
            response = func(url, **requests_args)
        except requests.RequestException as e:
            raise Exception(unicode(e))

        # create stash for last function intel
        self._last_call = {
            'api_call': api_call,
            'api_error': None,
            'cookies': response.cookies,
            'headers': response.headers,
            'status_code': response.status_code,
            'url': response.url,
            'content': response.text,
        }

        # greater than 304 (not modified) is an error
        if response.status_code > 304:
            error_message = self._get_error_message(response)
            self._last_call['api_error'] = error_message

            ExceptionType = TviTTERError
            if response.status_code == 429:
                # Twitter API 1.1, always return 429 when
                # rate limit is exceeded
                ExceptionType = TviTTERError
            elif response.status_code == 401 or 'Bad Authentication data' in error_message:
                # Twitter API 1.1, returns a 401 Unauthorized or
                # a 400 "Bad Authentication data" for invalid/expired
                # app keys/user tokens
                ExceptionType = TviTTERError

            raise ExceptionType(
                error_message,
                error_code=response.status_code,
                retry_after=response.headers.get('X-Rate-Limit-Reset'))

        try:
            if response.status_code == 204:
                content = response.content
            else:
                content = response.json()
        except ValueError:
            raise Exception('Response was not valid JSON. \
                               Unable to decode.')

        return content

    def _get_error_message(self, response):
        """Parse and return the first error message"""

        error_message = 'An error occurred processing your request.'
        try:
            content = response.json()
            # {"errors":[{"code":34,"message":"Sorry,
            # that page does not exist"}]}
            error_message = content['errors'][0]['message']
        except TypeError:
            error_message = content['errors']
        except ValueError:
            # bad json data from Twitter for an error
            pass
        except (KeyError, IndexError):
            # missing data so fallback to default message
            pass

        return error_message

    def request(self, endpoint, method='GET', params=None, version='1.1'):
        """Return dict of response received from Twitter's API

        :param endpoint: (required) Full url or Twitter API endpoint
                         (e.g. search/tweets)
        :type endpoint: string
        :param method: (optional) Method of accessing data, either
                       GET or POST. (default GET)
        :type method: string
        :param params: (optional) Dict of parameters (if any) accepted
                       the by Twitter API endpoint you are trying to
                       access (default None)
        :type params: dict or None
        :param version: (optional) Twitter API version to access
                        (default 1.1)
        :type version: string

        :rtype: dict
        """

        if endpoint.startswith('http://'):
            raise Exception('api.twitter.com is restricted to SSL/TLS traffic.')

        # In case they want to pass a full Twitter URL
        # i.e. https://api.twitter.com/1.1/search/tweets.json
        if endpoint.startswith('https://'):
            url = endpoint
        else:
            """This is used when we are using the api via command line"""
            url = '%s/%s.json' % (self.api_url % version, endpoint)

        content = self._request(url, method=method, params=params,
                                api_call=url)

        return content

    def get(self, endpoint, params=None, version='1.1'):
        """Shortcut for GET requests via :class:`request`"""
        return self.request(endpoint, params=params, version=version)

    def post(self, endpoint, params=None, version='1.1'):
        """Shortcut for POST requests via :class:`request`"""
        #Mosty the params would be status
        return self.request(endpoint, 'POST', params=params, version=version)

    def get_lastfunction_header(self, header, default_return_value=None):
        """Returns a specific header from the last API call
        This will return None if the header is not present

        :param header: (required) The name of the header you want to get
                       the value of

        Most useful for the following header information:
            x-rate-limit-limit,
            x-rate-limit-remaining,
            x-rate-limit-class,
            x-rate-limit-reset

        """
        if self._last_call is None:
            raise Exception('This function must be called after an API call. \
                               It delivers header information.')

        return self._last_call['headers'].get(header, default_return_value)

    def get_authentication_tokens(self, callback_url=None, force_login=False,
                                  screen_name=''):
        """Returns a dict including an authorization URL, ``auth_url``, to
           direct a user to

        :param callback_url: (optional) Url the user is returned to after
                             they authorize your app (web clients only)
        :param force_login: (optional) Forces the user to enter their
                            credentials to ensure the correct users
                            account is authorized.
        :param screen_name: (optional) If forced_login is set OR user is
                            not currently logged in, Prefills the username
                            input box of the OAuth login screen with the
                            given value

        :rtype: dict
        """
        if self.oauth_version != 1:
            raise Exception('This method can only be called when your \
                               OAuth version is 1.0.')

        request_args = {}
        if callback_url:
            request_args['oauth_callback'] = callback_url
        response = self.client.get(self.request_token_url, params=request_args)

        if response.status_code == 401:
            raise Exception( str(response.content) + str(response.status_code))
        elif response.status_code != 200:
            raise TviTTERException(response.content,
                               error_code=response.status_code)

        request_tokens = dict(parse_qsl(response.content.decode('utf-8')))
        if not request_tokens:
            raise Exception('Unable to decode request tokens.')

        oauth_callback_confirmed = request_tokens.get('oauth_callback_confirmed') \
            == 'true'

        auth_url_params = {
            'oauth_token': request_tokens['oauth_token'],
        }

        if force_login:
            auth_url_params.update({
                'force_login': force_login,
                'screen_name': screen_name
            })

        # Use old-style callback argument if server didn't accept new-style
        if callback_url and not oauth_callback_confirmed:
            auth_url_params['oauth_callback'] = self.callback_url

        request_tokens['auth_url'] = self.authenticate_url + \
            '?' + urlencode(auth_url_params)

        return request_tokens

    def get_authorized_tokens(self, oauth_verifier):
        """Returns a dict of authorized tokens after they go through the
        :class:`get_authentication_tokens` phase.

        :param oauth_verifier: (required) The oauth_verifier (or a.k.a PIN
        for non web apps) retrieved from the callback url querystring
        :rtype: dict

        """
        if self.oauth_version != 1:
            raise Exception('This method can only be called when your \
                               OAuth version is 1.0.')

        response = self.client.get(self.access_token_url,
                                   params={'oauth_verifier': oauth_verifier},
                                   headers={'Content-Type': 'application/\
                                   json'})

        if response.status_code == 401:
            try:
                try:
                    # try to get json
                    content = response.json()
                except AttributeError:  # pragma: no cover
                    # if unicode detected
                    content = json.loads(response.content)
            except ValueError:
                content = {}
            message = "error_code="  + str(response.status_code)
            raise Exception(message)
        authorized_tokens = dict(parse_qsl(response.content.decode('utf-8')))
        if not authorized_tokens:
            raise Exception('Unable to decode authorized tokens.')

        return authorized_tokens  # pragma: no cover

    def obtain_access_token(self):
        """Returns an OAuth 2 access token to make OAuth 2 authenticated
        read-only calls.

        :rtype: string
        """
        if self.oauth_version != 2:
            raise Exception('This method can only be called when your \
                               OAuth version is 2.0.')

        data = {'grant_type': 'client_credentials'}
        basic_auth = HTTPBasicAuth(self.app_key, self.app_secret)
        try:
            response = self.client.post(self.request_token_url,
                                        data=data, auth=basic_auth)
                                        
            content = response.content.decode('utf-8')
            try:
                content = content.json()
            except AttributeError:
                content = json.loads(content)
                access_token = content['access_token']
        except (KeyError, ValueError, requests.exceptions.RequestException):
            raise Exception('Unable to obtain OAuth 2 access token.')
        else:
            return access_token

    @staticmethod
    def construct_api_url(api_url, **params):
        """Construct a Twitter API url, encoded, with parameters

        :param api_url: URL of the Twitter API endpoint you are attempting
        to construct
        :param \*\*params: Parameters that are accepted by Twitter for the
        endpoint you're requesting
        :rtype: string

        Usage::

          >>> from twython import Twython
          >>> twitter = Twython()

          >>> api_url = 'https://api.twitter.com/1.1/search/tweets.json'
          >>> constructed_url = twitter.construct_api_url(api_url, q='python',
          result_type='popular')
          >>> print constructed_url
          https://api.twitter.com/1.1/search/tweets.json?q=python&result_type=popular

        """
        querystring = []
        params, _ = _transparent_params(params or {})
        params = requests.utils.to_key_val_list(params)
        for (k, v) in params:
            querystring.append(
                '%s=%s' % (Twython.encode(k), quote_plus(Twython.encode(v)))
            )
        return '%s?%s' % (api_url, '&'.join(querystring))


    @staticmethod
    def unicode2utf8(text):
        try:
            if is_py2 and isinstance(text, unicode):
                text = text.encode('utf-8')
        except:
            pass
        return text

    @staticmethod
    def encode(text):
        if is_py2 and isinstance(text, (unicode)):
            return Twython.unicode2utf8(text)
        return unicode(text)

        
        
