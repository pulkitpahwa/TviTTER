from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required

import datetime
import json
import requests

from TviTTER.settings import APP_KEY, APP_SECRET
from TviTTER.getting_Started import TviTTER

def home(request):
    if request.user.is_anonymous() :
        return HttpResponse("unregistered user")
    else : 
        return HttpResponse("registered user")

@login_required
def blog(request):
    twitter = TviTTER(APP_KEY, APP_SECRET)
    auth = twitter.get_authentication_tokens()
    OAUTH_TOKEN = auth['oauth_token']
    OAUTH_TOKEN_SECRET = auth['oauth_token_secret']
    request.session['OAUTH_TOKEN'] = OAUTH_TOKEN
    request.session['OAUTH_TOKEN_SECRET'] = OAUTH_TOKEN_SECRET
    return HttpResponseRedirect(auth['auth_url'])

@login_required
def find_oauth_verifier(request):
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
        user_access = twitter.get_authorized_tokens(oauth_verifier)

        OAUTH_TOKEN =  user_access['oauth_token']
        OAUTH_TOKEN_SECRET = user_access['oauth_token_secret']

        authorized_user = TviTTER( APP_KEY, APP_SECRET,  OAUTH_TOKEN, OAUTH_TOKEN_SECRET )
#        authorized_user.update_status(status=status)
        video = request.FILES['video_file']
#        video = open(video, "rb")
        try :
            response = authorized_user.upload_video(media=video, media_type='video/mp4')
        except : 
            return HttpResponse("invalid format")
        authorized_user.update_status(status=status, media_ids=[response['media_id']])

        return render_to_response("form.html",{"message":"status successfully updated"}, context_instance = RequestContext(request))

    

