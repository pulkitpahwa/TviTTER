
# TviTTER: Twitter Video status update project
#####A django based project that let users to update their twitter status with video.

This project is aimed to be used as a web backend for tweeting on twitter from a website.

 
##How to use

Go to https://apps.twitter.com and create an app for yourself. 
Make sure that you have set the read and write permissions of the app to True.
Set the callback_url of the app to YOUR_DOMAIN_NAME/upload_video/
Create app_key.py file in TviTTER/TviTTER/ folder 

Sample app_key.py : 
```
    APP_KEY = YOUR_APP_KEY
    APP_SECRET = YOUR_APP_SECRET

```






