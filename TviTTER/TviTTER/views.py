from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout

import datetime
import json
import requests

from TviTTER.settings import APP_KEY, APP_SECRET
from TviTTER.getting_Started import TviTTER, TviTTERError


@login_required
def home(request):
    return render_to_response("index.html",{}, context_instance = RequestContext(request))

@login_required
def authenticate_user(request):
    twitter = TviTTER(APP_KEY, APP_SECRET)
    auth = twitter.get_authentication_tokens()
    OAUTH_TOKEN = auth['oauth_token']
    OAUTH_TOKEN_SECRET = auth['oauth_token_secret']
    request.session['OAUTH_TOKEN'] = OAUTH_TOKEN
    request.session['OAUTH_TOKEN_SECRET'] = OAUTH_TOKEN_SECRET
    return HttpResponseRedirect(auth['auth_url'])

@login_required
def upload_video(request):
    if request.method == "GET" : 
        oauth_verifier = request.GET['oauth_verifier']
        request.session['oauth_verifier'] = oauth_verifier
        return render_to_response("form.html",{}, context_instance = RequestContext(request))
    if request.method == "POST" : 
        status = request.POST['tweet']
        OAUTH_TOKEN = request.session['OAUTH_TOKEN']
        OAUTH_TOKEN_SECRET = request.session['OAUTH_TOKEN_SECRET']
        twitter = TviTTER(APP_KEY, APP_SECRET, OAUTH_TOKEN, OAUTH_TOKEN_SECRET)
        oauth_verifier = request.session['oauth_verifier']
        try : 
            user_access = twitter.get_authorized_tokens(oauth_verifier)
        except : 
            return HttpResponse("Unable to authenticate you. Please try again")
        OAUTH_TOKEN =  user_access['oauth_token']
        OAUTH_TOKEN_SECRET = user_access['oauth_token_secret']
    
        authorized_user = TviTTER( APP_KEY, APP_SECRET,  OAUTH_TOKEN, OAUTH_TOKEN_SECRET )
        authorized_user.update_status(status = status)
#        video = request.FILES['video_file']
#        try :
#           response = authorized_user.upload_video(media=video, media_type='video/mp4')
#        except : 
#            return render_to_response("video_format_error.html",{}, context_instance = RequestContext(request)) 
#        try : 
#            authorized_user.update_status(status=status, media_ids=[response['media_id']])
#        except TviTTERError : 
#            return HttpResponse("status already exist. Duplicate status")
        return HttpResponseRedirect('/')


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
            login(request, u)
            return HttpResponse(u.username)
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

    

