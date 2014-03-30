from flask import render_template
from flask.ext.mail import Message
from app import app, mail
from decorators import async
from config import ADMINS

@async    
def send_async_email(msg):
    with app.app_context():
        mail.send(msg)
    
def send_email(subject, sender, recipients, text_body, html_body):
    msg = Message(subject, sender = sender, recipients = recipients)
    msg.body = text_body
    msg.html = html_body
    send_async_email(msg)
    #thr = threading.Thread(target = send_async_email, args = [msg])
    #thr.start()

    
def follower_notification(followed, follower):
    send_email("[PrayerFirst] %s is now following you!" % follower.nickname,
        ADMINS[0],
        [followed.email],
        render_template("follower_email.txt", 
            user = followed, follower = follower),
        render_template("follower_email.html", 
            user = followed, follower = follower))
        
def group_invite(group, recipients):
    send_email("[PrayerFirst] You have been invited to join {0}".format(group.group_name),
        ADMINS[0],
        recipients,
        render_template("group_invite.txt",
            group = group),
        render_template("group_invite.html",
            group = group))
