from os import sync
from flask import flash,Flask, redirect, request, render_template, session, url_for
from ldap3.utils.dn import safe_rdn
from models import disableUser,enableStaff,disableStaff,disabledallStaffs,authenticate,allUsers,allStaffs,disableUser,allServiceAccounts,loggedUserInfo, appconfigurations,allGroups, userInfo, groupMembers, getStats,usertounlock,allConsultants,userCheck,lockedUsers,resetpassword,removefromgroup,appServiceAccount,ITusers
from initialSync import importStatus,syncAllStaff
from flask_mail import Mail, Message
from datetime import date,datetime,timedelta
from apscheduler.schedulers.background import BackgroundScheduler
import sqlite3 as db
from apscheduler.schedulers.blocking import BlockingScheduler
import json
from passlib.context import CryptContext
import time
import pygal
from pygal.style import Style
import pandas 
from crontab import CronTab

pwd_context = CryptContext(
        schemes=["pbkdf2_sha256"],
        default="pbkdf2_sha256",
        pbkdf2_sha256__default_rounds=30000
)


#Mail set up
app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
app.config['MAIL_SERVER'] = 'smtp.office365.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'bksalaries@bk.rw'  # enter your email here
app.config['MAIL_DEFAULT_SENDER'] = 'bksalaries@bk.rw' # enter your email here
app.config['MAIL_PASSWORD'] = 'Mona1234Lisa' # enter your password here

mail = Mail(app)



loggedUser="";
serviceAccountsName=[];
serviceAccountsCreationDate=[];
serviceAccountsStatus=[];
serviceAccountsDescription=[];
serviceAccountsUsername=[];
serviceAccountsLastLogon=[]


countbk=[];
countbkc=[];
countbkt=[];
countbki=[];
othercount=[];
activecountbk=[];
activecountbkc=[];
activecountbkt=[];
activecountbki=[];
disabledcountbk=[];
disabledcountbkc=[];
disabledcountbkt=[];
disabledcountbki=[];
unknowncountbk=[];
unknowncountbkc=[];
unknowncountbkt=[];
unknowncountbki=[];
pwdnvrxprcountbk=[];
pwdnvrxprcountbkc=[];
pwdnvrxprcountbkt=[];
pwdnvrxprcountbki=[];

syncStatus=[];
syncTime=[];

@app.route("/", methods=['POST', 'GET'])
def initialconfiguration():
    LDAP_SERVER,LDAP_SERVER2,domain,smtpserver,port,securityprotocol,email,password,companyName,userReportWeek,userReportMonth,initialised=appconfigurations()
    if (initialised=="true"):
        return redirect("/login")
    else:
        return render_template("initialconfiguration.html")

@app.route("/save_initial_configuration", methods=['POST', 'GET'])
def save_initial_configuration():
    server1 = request.form['server1']
    server2 = request.form['server2']
    domain = request.form['domain']
    company = request.form['company']
    serviceAccountUsername = request.form['serviceAccountUsername']
    serviceAccountPassword = request.form['serviceAccountPassword']
    smtpserver = request.form['smtpserver']
    smtpport = request.form['smtpport']
    smtpemail = request.form['smtpemail']
    smtppassword = request.form['smtppassword']

    configdata = {}
    configdata['appConf'] = []
    configdata['domainConf'] = []
    configdata['emailConf'] = []
    configdata['saConf'] = []
    configdata['appConf'].append({
        'initialised': 'true'
    })
    configdata['domainConf'].append({
        'ldapserver1': server1,
        'ldapserver2': server2,
        'domain':domain
    })
    configdata['emailConf'].append({
        'smtpserver': smtpserver, 
        'port': smtpport,
        'securityprotocol': 'tls',
        'email':smtpemail,
        'password':pwd_context.hash(smtppassword),
    })
    configdata['saConf'].append({
        'serviceAccountUsername': serviceAccountUsername,
        'serviceAccountPassword': pwd_context.hash(serviceAccountPassword),
        'companyname':company
    })

    #return(pwd_context.decrypt("$pbkdf2-sha256$30000$AgDgHGMshbD23rt3rvW.Vw$Ko/GFRuWtUZFRVTUaMpou0pudajTNvEeHgMwDNR5t/o"))

    with open('static/data/config.txt', 'w') as outfile:
        json.dump(configdata, outfile)

    return redirect("/login")

@app.route("/login", methods=['POST', 'GET'])
def login():
    context = {}
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            response1,response2,response3 = authenticate(username, password)
            if response2 == "True":
                session['username']=username
                session['password']=password
                session['role']=response1
                session['status']=response3
                return redirect("/home")
            else:
                logout()
                error="You are not an admin.You do not have access to this service!"
                return render_template("login.html", error=error)

        except ValueError as err:
            logout()
            context["error"] = err
            return render_template("login.html", **context)

    return render_template("login.html", **context)


@app.route('/logout')
def logout():
	session.pop('username', None)
	return redirect('/')

def getInfo():
    
    getInfo.allStaff=[];
    getInfo.staffDepartments=[];
    getInfo.staffUsernames=[];
    getInfo.staffEmails=[];
    getInfo.staffTitles=[];
    getInfo.staffCompany=[];
    getInfo.staffStatus=[];
    getInfo.staffCreationDate=[];
    getInfo.staffPwdExpiryDate=[];
    getInfo.staffWithExpiryDates=[];
    getInfo.staffUsernameWithExpiryDates=[];
    getInfo.staffEmailsWithExpiryDates=[];

    getInfo.disabledallStaff=[];
    getInfo.disabledstaffDepartments=[];
    getInfo.disabledstaffUsernames=[];
    getInfo.disabledstaffEmails=[];
    getInfo.disabledstaffTitles=[];
    getInfo.disabledstaffCompany=[];
    getInfo.disabledstaffStatus=[];
    getInfo.disabledstaffCreationDate=[];
    
    getInfo.groupsNames=[];
    getInfo.groupsCreationDate=[];
    getInfo.groupMembersUsername=[];
    getInfo.groupMembersDisplayname=[];


    try:
        response101,response102=groupMembers("IT Support")
        response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response44=allStaffs()
        response12,response13,response14,response15,response16,response42=allServiceAccounts()
        allGroupsNames,allGroupsCreationDate=allGroups()
        response22,response23,response24,response25,response26,response27,response28,response29,response30,response31,response32,response33,response34,response35,response36,response37,response38,response39,response40,response41=getStats()

        for i in range(0,len(response1)):
            getInfo.allStaff.append(response1[i])

        for i in range(0,len(response2)):
            getInfo.staffDepartments.append(response2[i])

        for i in range(0,len(response3)):
            getInfo.staffUsernames.append(response3[i])

        for i in range(0,len(response4)):
            getInfo.staffEmails.append(response4[i])

        for i in range(0,len(response5)):
            getInfo.staffTitles.append(response5[i])

        for i in range(0,len(response6)):
            getInfo.staffCompany.append(response6[i])

        for i in range(0,len(response7)):
            getInfo.staffPwdExpiryDate.append(response7[i])

        for i in range(0,len(response8)):
            getInfo.staffWithExpiryDates.append(response8[i])

        for i in range(0,len(response9)):
            getInfo.staffEmailsWithExpiryDates.append(response9[i])

        for i in range(0,len(response44)):
            getInfo.staffUsernameWithExpiryDates.append(response44[i])

        for i in range(0,len(response10)):
            getInfo.staffStatus.append(response10[i])

        for i in range(0,len(response11)):
            getInfo.staffCreationDate.append(response11[i])    

        for i in range(0,len(response101)):
            getInfo.groupMembersUsername.append(response101[i])

        for i in range(0,len(response102)):
            getInfo.groupMembersDisplayname.append(response102[i])

        for i in range(0,len(response12)):
            serviceAccountsName.append(response12[i])

        for i in range(0,len(response13)):
            serviceAccountsCreationDate.append(response13[i])

        for i in range(0,len(response14)):
            serviceAccountsStatus.append(response14[i])
        
        for i in range(0,len(response15)):
            serviceAccountsDescription.append(response15[i])

        for i in range(0,len(response16)):
            serviceAccountsUsername.append(response16[i])
        
        for i in range(0,len(response42)):
            serviceAccountsLastLogon.append(response42[i])

        for i in range(0,len(allGroupsNames)):
            getInfo.groupsNames.append(allGroupsNames[i])
        
        for i in range(0,len(allGroupsCreationDate)):
            getInfo.groupsCreationDate.append(allGroupsCreationDate[i])

        countbk.append(response22)
        activecountbk.append(response23)
        disabledcountbk.append(response24)
        unknowncountbk.append(response25)
        pwdnvrxprcountbk.append(response26)

        countbkc.append(response27)
        activecountbkc.append(response28)
        disabledcountbkc.append(response29)
        unknowncountbkc.append(response30)
        pwdnvrxprcountbkc.append(response31)

        countbkt.append(response32)
        activecountbkt.append(response33)
        disabledcountbkt.append(response34)
        unknowncountbkt.append(response35)
        pwdnvrxprcountbkt.append(response36)

        countbki.append(response37)
        activecountbki.append(response38)
        disabledcountbki.append(response39)
        unknowncountbki.append(response40)
        pwdnvrxprcountbki.append(response41)
        
        userSyncStatus,userSyncTime=importStatus()
        syncStatus.append(userSyncStatus)
        syncTime.append(userSyncTime)
    
    except Exception as ex:
        syncStatus.append("Failed")
        syncTime.append(datetime.now())

lockedUserFullname=[]
lockedUserUsername=[]
lockedUserLockoutTime=[]

@app.route("/home",methods=['GET','POST'])
def home():
    if session['username']=='':
        error="You need to login first before accessing that page!"
        return render_template("login.html", error=error)
    else:
        loggedUser,loggedtitle=loggedUserInfo(session['username'])
        synchroTime=syncTime[len(syncTime)-1]

        return render_template("home.html",pwdExpiryDate=getInfo.staffPwdExpiryDate,
                                        len1=len(getInfo.staffPwdExpiryDate),staffWithExpiryDates=getInfo.staffWithExpiryDates,
                                        staffEmailsWithExpiryDates=getInfo.staffEmailsWithExpiryDates,
                                        staffUsernameWithExpiryDates=getInfo.staffUsernameWithExpiryDates,
                                        staffCreationDate=getInfo.staffCreationDate,
                                        loggedUser=loggedUser,loggedtitle=loggedtitle,
                                        syncStatus=syncStatus[0],syncTime=synchroTime,
                                        countbk=countbk[0],activecountbk=activecountbk[0],disabledcountbk=disabledcountbk[0],
                                        pwdnvrxprcountbk=pwdnvrxprcountbk[0],countbkc=countbkc[0],activecountbkc=activecountbkc[0],
                                        disabledcountbkc=disabledcountbkc[0], pwdnvrxprcountbkc=pwdnvrxprcountbkc[0],
                                        countbkt=countbkt[0],activecountbkt=activecountbkt[0],
                                        disabledcountbkt=disabledcountbkt[0], pwdnvrxprcountbkt=pwdnvrxprcountbkt[0],
                                        countbki=countbki[0],activecountbki=activecountbki[0],
                                        disabledcountbki=disabledcountbki[0], pwdnvrxprcountbki=pwdnvrxprcountbki[0],
                                        unknowncountbk=unknowncountbk[0],unknowncountbkc=unknowncountbkc[0],
                                        unknowncountbki=unknowncountbki[0],unknowncountbkt=unknowncountbkt[0],role=session['role'])

@app.route("/staff",methods=['GET','POST'])
def staff():

    getInfo.allStaff=[];
    getInfo.staffDepartments=[];
    getInfo.staffUsernames=[];
    getInfo.staffEmails=[];
    getInfo.staffTitles=[];
    getInfo.staffCompany=[];
    getInfo.staffStatus=[];
    getInfo.staffCreationDate=[];
    getInfo.staffPwdExpiryDate=[];
    getInfo.staffWithExpiryDates=[];
    getInfo.staffUsernameWithExpiryDates=[];
    getInfo.staffEmailsWithExpiryDates=[];

    response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response44=allStaffs()
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    for i in range(0,len(response1)):
            getInfo.allStaff.append(response1[i])

    for i in range(0,len(response2)):
        getInfo.staffDepartments.append(response2[i])

    for i in range(0,len(response3)):
        getInfo.staffUsernames.append(response3[i])

    for i in range(0,len(response4)):
        getInfo.staffEmails.append(response4[i])

    for i in range(0,len(response5)):
        getInfo.staffTitles.append(response5[i])

    for i in range(0,len(response6)):
        getInfo.staffCompany.append(response6[i])

    for i in range(0,len(response7)):
        getInfo.staffPwdExpiryDate.append(response7[i])

    for i in range(0,len(response8)):
        getInfo.staffWithExpiryDates.append(response8[i])

    for i in range(0,len(response9)):
        getInfo.staffEmailsWithExpiryDates.append(response9[i])

    for i in range(0,len(response44)):
        getInfo.staffUsernameWithExpiryDates.append(response44[i])

    for i in range(0,len(response10)):
        getInfo.staffStatus.append(response10[i])

    for i in range(0,len(response11)):
        getInfo.staffCreationDate.append(response11[i])

    return render_template("staff.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                                            len=len(getInfo.allStaff),allStaff=getInfo.allStaff,department=getInfo.staffDepartments,
                                            username=getInfo.staffUsernames,email=getInfo.staffEmails,title=getInfo.staffTitles,staffStatus=getInfo.staffStatus,
                                            companies=getInfo.staffCompany, staffCreationDate=getInfo.staffCreationDate,
                                            serviceAccountsName=serviceAccountsName,serviceAccountsCreationDate=serviceAccountsCreationDate,
                                            serviceAccountsStatus=serviceAccountsStatus,serviceAccountsDescription=serviceAccountsDescription,
                                            len3=len(serviceAccountsName),serviceAccountsUsername=serviceAccountsUsername,
                                            serviceAccountsLastLogon=serviceAccountsLastLogon,role=session['role'])

@app.route("/bkstaff",methods=['GET','POST'])
def bkstaff():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    allStaff=[];
    staffDepartments=[];
    staffUsernames=[];
    staffEmails=[];
    staffTitles=[];
    staffCompany=[];
    staffStatus=[];
    staffCreationDate=[];
    staffPwdExpiryDate=[];
    staffWithExpiryDates=[];
    staffUsernameWithExpiryDates=[];
    staffEmailsWithExpiryDates=[];

    response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response44=allStaffs()
    
    for i in range(0,len(response1)):
        allStaff.append(response1[i])

    for i in range(0,len(response2)):
        staffDepartments.append(response2[i])

    for i in range(0,len(response3)):
        staffUsernames.append(response3[i])

    for i in range(0,len(response4)):
        staffEmails.append(response4[i])

    for i in range(0,len(response5)):
        staffTitles.append(response5[i])

    for i in range(0,len(response6)):
        staffCompany.append(response6[i])

    for i in range(0,len(response7)):
        staffPwdExpiryDate.append(response7[i])

    for i in range(0,len(response8)):
        staffWithExpiryDates.append(response8[i])

    for i in range(0,len(response9)):
        staffEmailsWithExpiryDates.append(response9[i])

    for i in range(0,len(response44)):
        staffUsernameWithExpiryDates.append(response44[i])

    for i in range(0,len(response10)):
        staffStatus.append(response10[i])

    for i in range(0,len(response11)):
        staffCreationDate.append(response11[i])

    return render_template("bkstaff.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                            len=len(allStaff),allStaff=allStaff,department=staffDepartments,
                            username=staffUsernames,email=staffEmails,title=staffTitles,staffStatus=staffStatus,
                            companies=staffCompany, staffCreationDate=staffCreationDate,)

@app.route("/bktstaff",methods=['GET','POST'])
def bktstaff():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    allStaff=[];
    staffDepartments=[];
    staffUsernames=[];
    staffEmails=[];
    staffTitles=[];
    staffCompany=[];
    staffStatus=[];
    staffCreationDate=[];
    staffPwdExpiryDate=[];
    staffWithExpiryDates=[];
    staffUsernameWithExpiryDates=[];
    staffEmailsWithExpiryDates=[];

    response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response44=allStaffs()
    
    for i in range(0,len(response1)):
        allStaff.append(response1[i])

    for i in range(0,len(response2)):
        staffDepartments.append(response2[i])

    for i in range(0,len(response3)):
        staffUsernames.append(response3[i])

    for i in range(0,len(response4)):
        staffEmails.append(response4[i])

    for i in range(0,len(response5)):
        staffTitles.append(response5[i])

    for i in range(0,len(response6)):
        staffCompany.append(response6[i])

    for i in range(0,len(response7)):
        staffPwdExpiryDate.append(response7[i])

    for i in range(0,len(response8)):
        staffWithExpiryDates.append(response8[i])

    for i in range(0,len(response9)):
        staffEmailsWithExpiryDates.append(response9[i])

    for i in range(0,len(response44)):
        staffUsernameWithExpiryDates.append(response44[i])

    for i in range(0,len(response10)):
        staffStatus.append(response10[i])

    for i in range(0,len(response11)):
        staffCreationDate.append(response11[i])

    return render_template("bktstaff.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                            len=len(allStaff),allStaff=allStaff,department=staffDepartments,
                            username=staffUsernames,email=staffEmails,title=staffTitles,staffStatus=staffStatus,
                            companies=staffCompany, staffCreationDate=staffCreationDate,)

@app.route("/bkistaff",methods=['GET','POST'])
def bkistaff():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    allStaff=[];
    staffDepartments=[];
    staffUsernames=[];
    staffEmails=[];
    staffTitles=[];
    staffCompany=[];
    staffStatus=[];
    staffCreationDate=[];
    staffPwdExpiryDate=[];
    staffWithExpiryDates=[];
    staffUsernameWithExpiryDates=[];
    staffEmailsWithExpiryDates=[];

    response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response44=allStaffs()
    
    for i in range(0,len(response1)):
        allStaff.append(response1[i])

    for i in range(0,len(response2)):
        staffDepartments.append(response2[i])

    for i in range(0,len(response3)):
        staffUsernames.append(response3[i])

    for i in range(0,len(response4)):
        staffEmails.append(response4[i])

    for i in range(0,len(response5)):
        staffTitles.append(response5[i])

    for i in range(0,len(response6)):
        staffCompany.append(response6[i])

    for i in range(0,len(response7)):
        staffPwdExpiryDate.append(response7[i])

    for i in range(0,len(response8)):
        staffWithExpiryDates.append(response8[i])

    for i in range(0,len(response9)):
        staffEmailsWithExpiryDates.append(response9[i])

    for i in range(0,len(response44)):
        staffUsernameWithExpiryDates.append(response44[i])

    for i in range(0,len(response10)):
        staffStatus.append(response10[i])

    for i in range(0,len(response11)):
        staffCreationDate.append(response11[i])

    return render_template("bkistaff.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                            len=len(allStaff),allStaff=allStaff,department=staffDepartments,
                            username=staffUsernames,email=staffEmails,title=staffTitles,staffStatus=staffStatus,
                            companies=staffCompany, staffCreationDate=staffCreationDate,)

@app.route("/bkcstaff",methods=['GET','POST'])
def bkcstaff():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    allStaff=[];
    staffDepartments=[];
    staffUsernames=[];
    staffEmails=[];
    staffTitles=[];
    staffCompany=[];
    staffStatus=[];
    staffCreationDate=[];
    staffPwdExpiryDate=[];
    staffWithExpiryDates=[];
    staffUsernameWithExpiryDates=[];
    staffEmailsWithExpiryDates=[];

    response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response44=allStaffs()
    
    for i in range(0,len(response1)):
        allStaff.append(response1[i])

    for i in range(0,len(response2)):
        staffDepartments.append(response2[i])

    for i in range(0,len(response3)):
        staffUsernames.append(response3[i])

    for i in range(0,len(response4)):
        staffEmails.append(response4[i])

    for i in range(0,len(response5)):
        staffTitles.append(response5[i])

    for i in range(0,len(response6)):
        staffCompany.append(response6[i])

    for i in range(0,len(response7)):
        staffPwdExpiryDate.append(response7[i])

    for i in range(0,len(response8)):
        staffWithExpiryDates.append(response8[i])

    for i in range(0,len(response9)):
        staffEmailsWithExpiryDates.append(response9[i])

    for i in range(0,len(response44)):
        staffUsernameWithExpiryDates.append(response44[i])

    for i in range(0,len(response10)):
        staffStatus.append(response10[i])

    for i in range(0,len(response11)):
        staffCreationDate.append(response11[i])

    return render_template("bkcstaff.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                            len=len(allStaff),allStaff=allStaff,department=staffDepartments,
                            username=staffUsernames,email=staffEmails,title=staffTitles,staffStatus=staffStatus,
                            companies=staffCompany, staffCreationDate=staffCreationDate,)

@app.route("/serviceaccounts",methods=['GET','POST'])
def serviceaccounts():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    
    response1,response2,response3,response4,response5,response6=allServiceAccounts()
    
    serviceAccountsName=[];
    serviceAccountsCreationDate=[];
    serviceAccountsStatus=[];
    serviceAccountsDescription=[];
    serviceAccountsUsername=[];
    serviceAccountsLastLogon=[]


    for i in range(0,len(response1)):
        serviceAccountsName.append(response1[i])

    for i in range(0,len(response2)):
        serviceAccountsCreationDate.append(response2[i])

    for i in range(0,len(response3)):
        serviceAccountsStatus.append(response3[i])
    
    for i in range(0,len(response4)):
        serviceAccountsDescription.append(response4[i])

    for i in range(0,len(response5)):
        serviceAccountsUsername.append(response5[i])
    
    for i in range(0,len(response6)):
        serviceAccountsLastLogon.append(response6[i])

    return render_template("serviceaccounts.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                                            serviceAccountsName=serviceAccountsName,serviceAccountsCreationDate=serviceAccountsCreationDate,
                                            serviceAccountsStatus=serviceAccountsStatus,serviceAccountsDescription=serviceAccountsDescription,
                                            len3=len(serviceAccountsName),serviceAccountsUsername=serviceAccountsUsername,
                                            serviceAccountsLastLogon=serviceAccountsLastLogon,role=session['role'])

@app.route("/consultants",methods=['GET','POST'])
def consultants():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    response1,response2,response3,response4,response5,response6=allConsultants()
    consultantName=[];
    consultantCreationDate=[];
    consultantStatus=[];
    consultantDescription=[];
    consultantUsername=[];
    consultantLastLogon=[];

    for i in range(0,len(response1)):
            consultantName.append(response1[i])

    for i in range(0,len(response2)):
        consultantCreationDate.append(response2[i])

    for i in range(0,len(response3)):
        consultantStatus.append(response3[i])
    
    for i in range(0,len(response4)):
        consultantDescription.append(response4[i])

    for i in range(0,len(response5)):
        consultantUsername.append(response5[i])
    
    for i in range(0,len(response6)):
        consultantLastLogon.append(response6[i])

    return render_template("consultants.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                                            consultantName=consultantName,len4=len(consultantName),
                                            consultantCreationDate=consultantCreationDate,consultantStatus=consultantStatus,
                                            consultantDescription=consultantDescription,consultantUsername=consultantUsername,role=session['role'])



@app.route("/lockedusers",methods=['GET','POST'])
def lockedusers():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    my_var = request.args.get('var', None)
    lockedUserFullname,lockedUserUsername,lockedUserLockoutTime=lockedUsers()
    
    return render_template("lockedstaff.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                            syncStatus=syncStatus[0],syncTime=synchroTime,
                                            lockedUserFullname=lockedUserFullname,lockedUserUsername=lockedUserUsername,
                                            lockedUserLockoutTime=lockedUserLockoutTime,len2=len(lockedUserFullname),role=session['role'])


@app.route("/disabledstaff",methods=['GET','POST'])
def disabledstaff():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])

    response1,response2,response3,response4,response5,response6,response7,response8=disabledallStaffs()
    
    disabledallStaff=[];
    disabledstaffDepartments=[];
    disabledstaffUsernames=[];
    disabledstaffEmails=[];
    disabledstaffTitles=[];
    disabledstaffCompany=[];
    disabledstaffStatus=[];
    disabledstaffCreationDate=[];

    for i in range(0,len(response1)):
        disabledallStaff.append(response1[i])

    for i in range(0,len(response2)):
        disabledstaffDepartments.append(response2[i])

    for i in range(0,len(response3)):
        disabledstaffUsernames.append(response3[i])

    for i in range(0,len(response4)):
        disabledstaffEmails.append(response4[i])

    for i in range(0,len(response5)):
        disabledstaffTitles.append(response5[i])

    for i in range(0,len(response6)):
        disabledstaffCompany.append(response6[i])

    for i in range(0,len(response7)):
        disabledstaffStatus.append(response7[i])

    for i in range(0,len(response8)):
        disabledstaffCreationDate.append(response8[i])

    return render_template("disabledstaff.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                            syncStatus=syncStatus[0],syncTime=synchroTime,len=len(disabledallStaff),
                                            disabledallStaff=disabledallStaff,disabledstaffDepartments=disabledstaffDepartments,
                                            disabledstaffUsernames=disabledstaffUsernames,disabledstaffEmails=disabledstaffEmails,
                                            disabledstaffTitles=disabledstaffTitles,disabledstaffCompany=disabledstaffCompany,
                                            disabledstaffStatus=disabledstaffStatus,disabledstaffCreationDate=disabledstaffCreationDate,
                                            role=session['role'])


@app.route("/sendreminder",methods=['GET','POST'])
def sendreminder():
    my_var = request.args.get('my_var', None)
    msg = Message("Password expiry reminder!", recipients=['crugamba@bk.rw'])
    resetLink="http://127.0.0.1:5000/resetuserpassword?var=" + my_var
    msg.body = "This user needs to reset his password: " + my_var  +"\r\nTo reset your password, Please click here and follow the instructions: " + "\r\n" + resetLink
    mail.send(msg)
    return("Reminder email sent to: " + my_var)


@app.route("/userInformation",methods=['GET'])
def userInformation():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    my_var = request.args.get('var', None)
    userValidation=userCheck(my_var)
    if userValidation=="true":
        response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response12,response13,response14=userInfo(my_var)
        userFullname=str(response1)
        #return(response1 +" | "+response2+" | " +response3+" | "+response4+" | "+response5+" | "+response6+" | "+response7)
        
        return render_template("userinformation.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                    userFullname=userFullname,
                                                    username=response2,
                                                    useremail=response3,
                                                    usertitle=response4,
                                                    userdepartment=response5,
                                                    userstatus=response6,
                                                    usercreationdate=response7,
                                                    lastModified=response8,
                                                    memberOf=response9,
                                                    company=response10,
                                                    accountState=response11,
                                                    userMobileNumber=response12,
                                                    userValidation=userValidation,
                                                    pwdExpiryDate=response13,userDN=response14,
                                                    role=session['role'])
    else:
        return render_template("userinformation.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                    error="There is no user with that username!")


@app.route("/configuration",methods=['GET','POST'])
def configuration():
    synchroTime=syncTime[len(syncTime)-1]
    LDAP_SERVER,LDAP_SERVER2,domain,smtpserver,port,securityprotocol,email,password,companyName,userReportWeek,userReportMonth,initialised=appconfigurations()
    SAusername, SApassword=appServiceAccount()
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    if session['role']=="Full Access":
        print(password, SApassword)
        return render_template("configuration.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                    LDAP_SERVER=LDAP_SERVER,LDAP_SERVER2=LDAP_SERVER2,domain=domain,
                                    smtpserver=smtpserver,port=port, securityprotocol=securityprotocol,
                                    smtpemail=email,password=password,serviceAccountUsername=SAusername,
                                    serviceAccountPassword=SApassword,role=session['role'],
                                    companyName=companyName,syncStatus=syncStatus[0],syncTime=synchroTime)
    else:
        return render_template("norights.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                error="You do not have enough rights to view this page!")

@app.route("/accessmanagement",methods=['GET','POST'])
def accessmanagement():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    response1,response2,response3,response4,response5,response6,response7=allUsers()
    if session['role']=="Full Access":
        return render_template("accessmanagement.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                    usernames=response2,fullnames=response1,len=len(response1),
                                                    title=response3,rights=response4,date_added=response5,
                                                    last_logon=response6,role=session['role'],status=response7)
    else:
        return render_template("norights.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                error="You do not have enough rights to view this page!")

@app.route("/reports",methods=['GET','POST'])
def reports():
    LDAP_SERVER,LDAP_SERVER2,domain,smtpserver,port,securityprotocol,email,password,companyName,reportUserWeek,reportUserMonth,initialised=appconfigurations()
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    if session['role']=="Full Access":
        return render_template("reports.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                            syncStatus=syncStatus[0],syncTime=synchroTime,
                                            reportUserWeek=reportUserWeek,reportUserMonth=reportUserMonth,role=session['role'])
    else:
        return render_template("norights.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                error="You do not have enough rights to view this page!")

@app.route("/securitygroups",methods=['GET','POST'])
def securitygroups():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    if session['role']=="Full Access":
        return render_template("securitygroups.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                                                groupName=getInfo.groupsNames, len2=len(getInfo.groupsNames),groupCreationDate=getInfo.groupsCreationDate,
                                                groupMembersDisplayname=getInfo.groupMembersDisplayname,groupMembersUsername=getInfo.groupMembersUsername,
                                                len5=len(getInfo.groupMembersDisplayname),grpName="IT Support",role=session['role'])
    else:
        return render_template("norights.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                error="You do not have enough rights to view this page!")


@app.route("/securitygroupmembers",methods=['GET','POST'])
def securitygroupmembers():
    groupMembersUsername=[];
    groupMembersDisplayname=[];
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    my_var = request.args.get('var', None)
    response101,response102=groupMembers(my_var)
    for i in range(0,len(response101)):
        groupMembersUsername.append(response101[i])
        groupMembersDisplayname.append(response102[i])
    if session['role']=="Full Access":
        return render_template("securitygroups.html",loggedUser=loggedUser,loggedtitle=loggedtitle,syncStatus=syncStatus[0],syncTime=synchroTime,
                                            groupName=getInfo.groupsNames, len2=len(getInfo.groupsNames),groupCreationDate=getInfo.groupsCreationDate,
                                            groupMembersDisplayname=groupMembersDisplayname,groupMembersUsername=groupMembersUsername,
                                            len5=len(groupMembersDisplayname),grpName=my_var,role=session['role'])
    else:
        return render_template("norights.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                error="You do not have enough rights to view this page!")

@app.route("/resetuserpassword",methods=['GET','POST'])
def resetuserpassword():
    synchroTime=syncTime[len(syncTime)-1]
    my_var = request.args.get('var', None)
    my_var2= request.args.get('var2', None)
    return render_template("resetpassword.html",username=my_var)


@app.route("/resetuserpwd",methods=['GET','POST'])
def resetuserpwd():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    my_var = request.form['username']
    my_var1 = request.form['newpassword']
    my_var2 = request.form['newpassword2']
    if my_var1==my_var2:
        restpwdresult=resetpassword(my_var,my_var2)
        userValidation=userCheck(my_var)
        if userValidation=="true":
            response1,response2,response3,response4,response5,response6,response7,response8,response9,response10,response11,response12,response13,response14=userInfo(my_var)
            userFullname=str(response1)
            if restpwdresult=="Account Disabled":
                flash("User " + my_var + " has had his password reset")
                return render_template("userinformation.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                    userFullname=userFullname,
                                                    username=response2,
                                                    useremail=response3,
                                                    usertitle=response4,
                                                    userdepartment=response5,
                                                    userstatus=response6,
                                                    usercreationdate=response7,
                                                    lastModified=response8,
                                                    memberOf=response9,
                                                    company=response10,
                                                    accountState=response11,
                                                    userMobileNumber=response12,
                                                    userValidation=userValidation,
                                                    pwdExpiryDate=response13,userDN=response14,
                                                    role=session['role'])
            else:
                return render_template("userinformation.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                    syncStatus=syncStatus[0],syncTime=synchroTime,
                                                    error="There is no user with that username!")
    else:
        flash("The passwords do not match!")

@app.route("/unlockUser",methods=['GET','POST'])
def unlockUser():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    my_var = request.args.get('var', None)
    usertounlock(my_var)
    flash("User " + my_var + " has been unlocked")
    #return(response1 +" | "+response2+" | " +response3+" | "+response4+" | "+response5+" | "+response6+" | "+response7)
    return redirect(request.referrer)

@app.route("/grantaccess",methods=['GET','POST'])
def grantaccess():
    my_var = request.args.get('var', None)
    result=enableStaff(my_var)
    return (result)

@app.route("/revokeaccess",methods=['GET','POST'])
def revokeaccess():
    my_var = request.args.get('var', None)
    result=disableStaff(my_var)
    return (result)

@app.route("/removeuserfromgroup",methods=['GET','POST'])
def removeuserfromgroup():
    my_var = request.args.get('var', None)
    my_var2 = request.args.get('var2', None)
    result=removefromgroup(my_var,my_var2)
    if result=="Success":
        flash("User " + my_var + " has removed from " + my_var2)
        return redirect(request.referrer)
    else:
        flash("User " + my_var + " was not removed from " + my_var2)
        return redirect(request.referrer)

@app.route("/allusers",methods=['GET','POST'])
def allusers():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    my_var = request.args.get('var', None)
    return render_template("allusers.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                syncStatus=syncStatus[0],syncTime=synchroTime,
                                                username=my_var)

@app.route("/loginlogs",methods=['GET','POST'])
def loginlogs():
    synchroTime=syncTime[len(syncTime)-1]
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    if session['role']=="Full Access":
        return render_template("norights.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                syncStatus=syncStatus[0],syncTime=synchroTime,
                                                error="Nothing to show yet!")
    else:
        return render_template("norights.html",loggedUser=loggedUser,loggedtitle=loggedtitle,
                                                syncStatus=syncStatus[0],syncTime=synchroTime,
                                                error="You do not have enough rights to view this page!")

@app.route("/syncnow",methods=['POST'])
def syncnow():
    getInfo()
    syncAllStaff()
    return redirect(request.referrer)

@app.route("/newsecuritygroup",methods=['POST'])
def newsecuritygroup():
    return ("New Security Group Created")

@app.route("/addnewmember",methods=['POST'])
def addnewmember():
    return ("Member Added")

@app.route("/home2",methods=['GET','POST'])
def home2():
    loggedUser,loggedtitle=loggedUserInfo(session['username'])
    synchroTime=syncTime[len(syncTime)-1]
    return render_template('Home2.html', loggedUser=loggedUser,loggedtitle=loggedtitle,
                                        syncStatus=syncStatus[0],syncTime=synchroTime,role=session['role'])

@app.route('/bar_route')   
def bar_route():
    try:
        #print(int(str(countbk[0])))
        bar_chart = pygal.HorizontalBar()
        bar_chart.title = 'Browser usage evolution (in %)'
        bar_chart.x_labels = ("Active Staff","Disabled Staff")

        bar_chart.add('Bank of Kigali'+" " + str(activecountbk[0]) , [int(str(activecountbk[0])), int(str(disabledcountbk[0]))])
        bar_chart.add('BK Insurance'+" " + str(activecountbki[0]),   [int(str(activecountbki[0])), int(str(disabledcountbki[0]))])
        bar_chart.add('BK Capital'+" " + str(activecountbkc[0]),     [int(str(activecountbkc[0])), int(str(disabledcountbkc[0]))])
        bar_chart.add('BK Techouse'+" " + str(activecountbkt[0]),   [int(str(activecountbkt[0])), int(str(disabledcountbkt[0]))])
        barchart_data=bar_chart.render_data_uri()
        return render_template('barchart.html',barchart_data=barchart_data)

    except Exception as ex:
        return ex

#def some_job():
 #   syncAllStaff("crugamba","@Rcedou@2391!")

#scheduler = BlockingScheduler()
#scheduler.add_job(some_job, 'interval', minutes=5)
#scheduler.start()../

if __name__ == "__main__":
    getInfo()
    app.run(host="0.0.0.0", debug=True)