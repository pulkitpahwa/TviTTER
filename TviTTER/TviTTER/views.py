from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User

import datetime
import json
import requests

from TviTTER.settings import APP_KEY, APP_SECRET
import os
import requests
from requests.auth import HTTPBasicAuth
from requests_oauthlib import OAuth1
from urlparse import parse_qsl
from urllib import urlencode
from StringIO import StringIO

numeric_types = (int, long, float)
api_url = "https://api.twitter.com/%s"

def update_request(endpoint, api_url = None, client = None, params=None):
    """Internal request method"""
    if endpoint.startswith("http://"):
        return [True, "api.twitter.com is restricted to SSL/TLS traffic."]

    if endpoint.startswith("https://"):
        url = endpoint
    else:
        """This is used when we are using the api via command line"""
        url = "%s/%s.json" % (api_url % "1.1", endpoint)

    method = "post"
    params = params or {}
    
    func = getattr(client, method)
    
    data_params = {}
    files = {}
    for k, v in params.items():
        if hasattr(v, "read") and callable(v.read):
            files[k] = v  
        elif isinstance(v, basestring) or isinstance(v, numeric_types):
            data_params[k] = v
        else:
            continue  
            
    requests_args = {}
    requests_args.update({
        "data": data_params,
        "files": files,
    })
    try:
        response = func(url, **requests_args)
    except requests.RequestException as e:
        return [True, unicode(e)]


    if response.status_code > 304:
        try:
            content = response.json()
            error_message = content["errors"][0]["message"]
            return [True, error_message]
        except TypeError:
            error_message = content["errors"]
            return [True, error_message]
        except ValueError:
            return [True, "Response was not valid JSON. Unable to decode."]
        except (KeyError, IndexError):
            return [True, "file format Error"]

        
        if response.status_code == 429:
            return [True, "Rate Limit Exceeded"]
        elif response.status_code == 401 or "Bad Authentication data" in error_message:
            return [True, "Bad Authentication data. Invalid/expired app keys/user tokens"]
    try:
        if response.status_code == 204:
            content = response.content
        else:
            content = response.json()
    except ValueError:
        return [True, "Response was not valid JSON. Unable to decode."]
    return [False, content]



def update_status(api_url = None, client = None, **params):
    return update_request("statuses/update", api_url = api_url, client = client, params=params)

def upload_video(media, media_type, size=None, api_url = None, client = None):

    upload_url = "https://upload.twitter.com/1.1/media/upload.json"
    if not size:
        media.seek(0, os.SEEK_END)
        size = media.tell()
        media.seek(0)

    # Stage 1: INIT call
    params = {
        "command": "INIT",
        "media_type": media_type,
        "total_bytes": size
    }
    response_init = update_request(upload_url,api_url = api_url, client = client, params=params)
    if response_init[0] :
        return render_to_response("error.html", {"error":response_init[1]} , context_instance = RequestContext(request))
    media_id = response_init[1]["media_id"]

    # Stage 2: APPEND calls with 1mb chunks
    segment_index = 0
    while True:
        data = media.read(1*1024*1024)
        if not data:
            break
        media_chunk = StringIO()
        media_chunk.write(data)
        media_chunk.seek(0)

        params = {
            "command": "APPEND",
            "media_id": media_id,
            "segment_index": segment_index,
            "media": media_chunk,
        }
        update_request(upload_url,api_url = api_url, client = client, params=params)
        segment_index += 1

    # Stage 3: FINALIZE call to complete upload
    params = {
        "command": "FINALIZE",
        "media_id": media_id
    }
    return update_request(upload_url,api_url = api_url, client = client, params=params)



@login_required
def home(request):
    try : 
        message = request.GET['message']
    except :
        message = ""
    return render_to_response("index.html",{"message":message}, context_instance = RequestContext(request))

@login_required
def authenticate_user(request):
    auth = OAuth1(APP_KEY, APP_SECRET)
    client = requests.Session()
    client.auth = auth
    api_url = "https://api.twitter.com/%s"
    request_token_url = api_url % "oauth/request_token"
    response = client.get(request_token_url, params={})
    request_tokens = dict(parse_qsl(response.content.decode("utf-8")))

    authenticate_url = api_url % ("oauth/%s" % "authenticate")
    request_tokens["auth_url"] = authenticate_url + "?" + urlencode({"oauth_token" : request_tokens["oauth_token"]})
    OAUTH_TOKEN = request_tokens['oauth_token']
    OAUTH_TOKEN_SECRET = request_tokens['oauth_token_secret']
    request.session['OAUTH_TOKEN'] = OAUTH_TOKEN
    request.session['OAUTH_TOKEN_SECRET'] = OAUTH_TOKEN_SECRET

    return HttpResponseRedirect(request_tokens['auth_url'])

@login_required
def media_upload(request):
    if request.method == "GET" : 
        oauth_verifier = request.GET['oauth_verifier']
        request.session['oauth_verifier'] = oauth_verifier
        return render_to_response("form.html",{}, context_instance = RequestContext(request))
        
    elif request.method == "POST" : 
        status = request.POST['tweet']
        OAUTH_TOKEN = request.session['OAUTH_TOKEN']
        OAUTH_TOKEN_SECRET = request.session['OAUTH_TOKEN_SECRET']
 
        user_auth = OAuth1(APP_KEY, APP_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)
        client = requests.Session()
        client.auth = user_auth
        oauth_verifier = request.session['oauth_verifier']
        try : 
            access_token_url = api_url % "oauth/access_token"        
            response = client.get(access_token_url,
                       params={"oauth_verifier": oauth_verifier},
                       headers={"Content-Type": "application/json"})
            authorized_tokens = dict(parse_qsl(response.content.decode("utf-8")))
            print authorized_tokens
        except : 
            return HttpResponse("Unable to authenticate you. Please try again")
        OAUTH_TOKEN =  authorized_tokens["oauth_token"]
        OAUTH_TOKEN_SECRET = authorized_tokens["oauth_token_secret"]

        authorized_user = OAuth1(APP_KEY, APP_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)
        client = requests.Session()
        client.auth = authorized_user
        video = request.FILES['video_file']
        response = upload_video(media=video, media_type="video/mp4", api_url = api_url, client=client)
        if response[0]  : 
            return render_to_response("error.html", {"error" : response[1]} , context_instance = RequestContext(request))
        else : 
            update_status(api_url, client,status=request.POST['tweet'], media_ids=response[1]["media_id"])
        return HttpResponseRedirect('/?message=video uploaded successfully')


def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']

        try:
            u = User.objects.get(username = username) 
            return render_to_response("signup.html",{'error':"Username already taken"}, context_instance = RequestContext(request))
        except : 
            u = User.objects.create_user(username = username)
            u.set_password(password)
            u.is_staff = True
            u.is_active = True
            u.save()
            u = authenticate(username=username, password = password)
            u.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, u)
            return HttpResponseRedirect("/")
    else:
        return render_to_response("signup.html",{}, context_instance = RequestContext(request))


def user_login(request):
    context = RequestContext(request)
    try :
        title = request.GET['msg']
    except : 
        title = ""
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None and user.is_active:
            login(request, user)
            return HttpResponseRedirect("/")
        else:
            return render_to_response("login.html",{'error':"Username and password do not match", "title" : title},context_instance = context)
    else:
        return render_to_response('login.html', {"title" : title}, context_instance = context)
        

@login_required
def user_logout(request):
    logout(request)
    return HttpResponseRedirect('/accounts/login/?msg=successfully registered')

    

