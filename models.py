import os
from ldap3 import Server, Connection, ObjectDef, AttrDef, Reader, Writer, ALL, core
from ldap3.utils.dn import safe_rdn
import sqlite3 as db
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import date,datetime,timedelta
import json

if os.path.exists('/home/crugamba/SimpleADManager/static/data/config.txt'):
    with open('/home/crugamba/SimpleADManager/static/data/config.txt') as json_file:
        data=[json.loads(line) for line in json_file]
        appconf=data[0]
        domainConf=data[1]
        emailConf=data[2]
        saConf=data[3]
        for p in appconf['appConf']:
            initialised=p['initialised']

        for p in domainConf['domainConf']:
            LDAP_SERVER=p['ldapserver1']
            LDAP_SERVER2=p['ldapserver2']
            domain = p['domain']
        
        for p in emailConf['emailConf']:
            smtpserver=p['smtpserver']
            port=p['port']
            securityprotocol=p['securityprotocol']
            email=p['email']
            password=p['password']
        
        for p in saConf['saConf']:
            serviceAccountUsername=p['serviceAccountUsername']
            serviceAccountPassword=p['serviceAccountPassword']
            companyName=p['companyname']
            userReportWeek="on"
            userReportMonth="off"


    def appconfigurations():
        with open('/home/crugamba/SimpleADManager/static/data/config.txt') as json_file:
            data=[json.loads(line) for line in json_file]
            appconf=data[0]
            domainConf=data[1]
            emailConf=data[2]
            saConf=data[3]
            for p in appconf['appConf']:
                initialised=p['initialised']

            for p in domainConf['domainConf']:
                LDAP_SERVER=p['ldapserver1']
                LDAP_SERVER2=p['ldapserver2']
                domain = p['domain']
            
            for p in emailConf['emailConf']:
                smtpserver=p['smtpserver']
                port=p['port']
                securityprotocol=p['securityprotocol']
                email=p['email']
                password=p['password']
            
            for p in saConf['saConf']:
                serviceAccountUsername=p['serviceAccountUsername']
                serviceAccountPassword=p['serviceAccountPassword']
                companyName=p['companyname']
                userReportWeek="on"
                userReportMonth="off"

            return LDAP_SERVER,LDAP_SERVER2,domain,smtpserver,port,securityprotocol,email,password,companyName,userReportWeek,userReportMonth,initialised
else:
    configdata = {}
    configdata['appConf'] = []
    configdata['domainConf'] = []
    configdata['emailConf'] = []
    configdata['saConf'] = []
    configdata['appConf'].append({
        'initialised': 'false'
    })
    configdata['domainConf'].append({
        'ldapserver1': " ",
        'ldapserver2': " ",
        'domain':" "
    })
    configdata['emailConf'].append({
        'smtpserver': " ", 
        'port': " ",
        'securityprotocol': " ",
        'email':" ",
        'password':" ",
    })
    configdata['saConf'].append({
        'serviceAccountUsername': " ",
        'serviceAccountPassword': " ",
        'companyname':" "
    })

    #return(pwd_context.decrypt("$pbkdf2-sha256$30000$AgDgHGMshbD23rt3rvW.Vw$Ko/GFRuWtUZFRVTUaMpou0pudajTNvEeHgMwDNR5t/o"))

    with open('static/data/config.txt', 'w') as outfile:
        json.dump(configdata, outfile)

    def appconfigurations():
        with open('/home/crugamba/SimpleADManager/static/data/config.txt') as json_file:
            data=[json.loads(line) for line in json_file]
            appconf=data[0]
            domainConf=data[1]
            emailConf=data[2]
            saConf=data[3]
            for p in appconf['appConf']:
                initialised=p['initialised']

            for p in domainConf['domainConf']:
                LDAP_SERVER=p['ldapserver1']
                LDAP_SERVER2=p['ldapserver2']
                domain = p['domain']
            
            for p in emailConf['emailConf']:
                smtpserver=p['smtpserver']
                port=p['port']
                securityprotocol=p['securityprotocol']
                email=p['email']
                password=p['password']
            
            for p in saConf['saConf']:
                serviceAccountUsername=p['serviceAccountUsername']
                serviceAccountPassword=p['serviceAccountPassword']
                companyName=p['companyname']
                userReportWeek="on"
                userReportMonth="off"


def appServiceAccount():
  with open('/home/crugamba/SimpleADManager/static/data/config2.txt') as json_file:
    data2=json.load(json_file)
    for p in data2['config2']:
      appSAUsername=p['SAusername']
      appSApassword=p['SApassword']
    
      return appSAUsername,appSApassword

SAusername, SApassword=appServiceAccount()

LDAP_FILTER_GROUP = '(objectclass=group)'
LDAP_FILTER_USER = '(objectclass=person)'
LDAP_ATTRS = [ "sAMAccountName", "distinguishedName", "sn", "givenName",
                "pwdLastSet","userAccountControl","userPrincipalName",
                "department","displayName","title","mail","accountExpires",
                "member","lockoutTime","memberOf","whenCreated","company",
                "description","whenChanged","lockoutTime","mobile","lastLogon"]

locations =["Kigali","North","East","West","SOUTH","BK Insurance","BK TECHOUSE","BK Capital ltd","Indigo_Issuing","TLS1.2_Users,OU=Staff Computers","Nairobi"]

logpath ='Logs'
activityLogs='/activityLogs'
errorLogs='/errorLogs'
debug_level='DEBUG'

def activityLog(username):
    handlers = [
            RotatingFileHandler(filename=logpath+activityLogs, mode='w', maxBytes=512000, 
                                backupCount=4)
            ]
    d = {'clientip': '192.168.0.1', 'user': 'fbloggs'}
    logging.basicConfig(handlers=handlers, level=debug_level, 
                        format='%(levelname)s: %(asctime)s: %(message)s', 
                        datefmt='%m/%d/%Y%H:%M:%S %p')

    logger = logging.getLogger('my_logger')
    logger.info('Action 0001: %s', username + " logged in")

def errorLog(er):
    handlers = [
            RotatingFileHandler(filename=logpath+errorLogs, mode='w', maxBytes=512000, 
                                backupCount=4)
            ]
    #d = {'clientip': '192.168.0.1', 'user': 'fbloggs'}
    logging.basicConfig(handlers=handlers, level=debug_level, 
                        format='%(levelname)s %(asctime)s %(message)s', 
                        datefmt='%m/%d/%Y%H:%M:%S %p')

    logger = logging.getLogger('my_logger')
    logger.error('Error 0001: %s', er)

def enableStaff(username):
    con = db.connect("/home/crugamba/SimpleADManager/static/data/database.db")
    cur = con.cursor()
    cur.execute(''' UPDATE USERS SET STATUS='Enabled'  WHERE Username=?''',(username,))
    con.commit()
    return 'Enabled'
    #if results[0][0]=="Enabled":

def disableStaff(username):
    con = db.connect("/home/crugamba/SimpleADManager/static/data/database.db")
    cur = con.cursor()
    cur.execute(''' UPDATE USERS SET STATUS='Disabled'  WHERE Username=?''',(username,))
    con.commit()
    return 'Disabled'
    #if results[0][0]=="Enabled":



def authenticate(username,password):
        # Create the Server object with the given address.
        server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
        sevver2= Server(LDAP_SERVER2, get_info=ALL,use_ssl=True)
        LDAP_USER ="bk\\" + username
        LDAP_PASSWORD =password
        #Create a connection object, and bind with the given DN and password.
        LDAP_FILTER2 = "(&(objectClass=user)(sAMAccountName="+username+"))"
        conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
        try: 
            if not conn.bind():
              raise ValueError("Invalid credentials")
            # Print the resulting entries.
            else:
              con = db.connect("/home/crugamba/SimpleADManager/static/data/database.db")
              cur = con.cursor()
              cur.execute(''' SELECT * FROM USERS where USERNAME=?''',(username,))
              results=cur.fetchall();
              if results[0][2]==username:
                if results[0][7]=='Enabled':
                    if results[0][4]!='No Access':
                        exist="True"
                        dateToday=str(datetime.now()).split(".")[0]
                        cur.execute('''UPDATE USERS SET LAST_LOGON = ? WHERE USERNAME = ? ;''',(dateToday,username,))
                        con.commit()
                        return results[0][4],exist,results[0][4]
                    else:
                        activityLog(username)           
                        raise ValueError("You do not have access to this service!Contact the administrator and request for access!")
                else:
                    activityLog(username)           
                    raise ValueError("You are not authorized to use this service!An alert has been seent to the Administrator!")
              else:
                activityLog(username)           
                raise ValueError("You are not authorized to use this service!An alert has been seent to the Administrator!")

        except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            errorLog("Authentication failure: Please make sure you have entered the right credentials")
            raise ValueError("Authentication failure: Please make sure you have entered the right credentials")

            #print('LDAP Bind Failed: ', e)

        except core.exceptions.LDAPSocketOpenError as ex:
            # If the LDAP bind failed for reasons such as authentication failure.
            errorLog(ex)
            raise ValueError("Your credentials could not be verified! Please check that the connection to your Acive Directory is possible!")

def allUsers():

  staffFullNames =[];
  staffUsername=[];
  staffTitle=[];
  staffAddedDate=[];
  staffRights=[];
  staffLastLogon=[];
  staffStatus=[];

  con = db.connect("static/data/database.db")
  cur = con.cursor()

  try: 
      if not con.cursor():
        raise ValueError("Invalid credentials")
      else:
          cur.execute(''' SELECT * FROM USERS ''')
          results=cur.fetchall();
          for r in results:
              staffFullNames.append(str(r[1]))
              staffUsername.append(str(r[2]))
              staffTitle.append(str(r[3]))
              staffAddedDate.append(str(r[4]))
              staffRights.append(str(r[5]))
              staffLastLogon.append(str(r[6]))
              staffStatus.append(str(r[7]))

      con.close()
      return staffFullNames,staffUsername,staffTitle,staffAddedDate,staffRights,staffLastLogon,staffStatus

  except core.exceptions.LDAPBindError as e:
      # If the LDAP bind failed for reasons such as authentication failure.
      errorLog("Authentication failure: Please make sure you have entered the right credentials")
      raise ValueError(e)
      #print('LDAP Bind Failed: ', e)

  except core.exceptions.LDAPSocketOpenError as ex:
      # If the LDAP bind failed for reasons such as authentication failure.
      errorLog(ex)
      raise ValueError(ex)



def allServiceAccounts():
  
  serviceAccountsName=[];
  serviceAccountsCreationDate=[];
  serviceAccountsStatus=[];
  serviceAccountsDescription=[];
  serviceAccountsUsername=[];
  serviceAccountLastLogon=[];
  con = db.connect("static/data/database.db")
  cur = con.cursor()
  try: 
      #conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD,authentication='NTLM', auto_bind=True)
      # Perform a search for a pre-defined criteria.
      # Mention the search filter / filter type and attributes.
      if not con.cursor():
        raise ValueError("Invalid credentials")
      else:

        #cur.execute(''' SELECT * FROM STAFF where username=(?); ''', (searchuser,))
        cur.execute(''' SELECT * FROM SERVICE_ACCOUNT ''')
        results=cur.fetchall();
        for r in results:
          serviceAccountsName.append(str(r[1]))
          serviceAccountsUsername.append(str(r[2]))
          serviceAccountsDescription.append(str(r[3]))
          serviceAccountsCreationDate.append(str(r[5]))
          serviceAccountLastLogon.append(str(r[6]))
          if str(str(r[4]))=="512":
            serviceAccountsStatus.append("Enabled")
          elif str(str(r[4]))=="514" or str(str(r[4]))=="65536":
            serviceAccountsStatus.append("Disabled")
          elif str(str(r[4]))=="66048":
            serviceAccountsStatus.append("Password Never Expires")
          else:
            serviceAccountsStatus.append("Unknown")
      con.close()

      return serviceAccountsName,serviceAccountsCreationDate,serviceAccountsStatus,serviceAccountsDescription,serviceAccountsUsername,serviceAccountLastLogon
  except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            errorLog("Authentication failure: Please make sure you have entered the right credentials")
            raise ValueError(e)
            #print('LDAP Bind Failed: ', e)

  except core.exceptions.LDAPSocketOpenError as ex:
      # If the LDAP bind failed for reasons such as authentication failure.
      errorLog(ex)
      raise ValueError(ex)

def allConsultants():

  consultantName=[];
  consultantCreationDate=[];
  consultantStatus=[];
  consultantDescription=[];
  consultantUsername=[];
  consultantLastLogon=[];

  con = db.connect("static/data/database.db")
  cur = con.cursor()

  try: 
      if not con.cursor():
        raise ValueError("Invalid credentials")
      else:
          cur.execute(''' SELECT * FROM CONSULTANTS ''')
          results=cur.fetchall();
          for r in results:
              consultantName.append(str(r[1]))
              consultantCreationDate.append(str(r[5]))
              consultantDescription.append(str(r[3]))
              consultantUsername.append(str(r[2]))
              consultantLastLogon.append(str(r[6]))
              if str(str(r[4]))=="512":
                consultantStatus.append("Enabled")
              elif str(str(r[4]))=="514" or str(str(r[4]))=="65536":
                consultantStatus.append("Disabled")
              elif str(str(r[4]))=="66048":
                consultantStatus.append("Password Never Expires")
              else:
                consultantStatus.append("Unknown")
      con.close()
      return consultantName,consultantCreationDate,consultantStatus,consultantDescription,consultantUsername,consultantLastLogon
  except core.exceptions.LDAPBindError as e:
      # If the LDAP bind failed for reasons such as authentication failure.
      errorLog("Authentication failure: Please make sure you have entered the right credentials")
      raise ValueError(e)
      #print('LDAP Bind Failed: ', e)

  except core.exceptions.LDAPSocketOpenError as ex:
      # If the LDAP bind failed for reasons such as authentication failure.
      errorLog(ex)
      raise ValueError(ex)

staffCompany=[];
staffStatus=[];

def allStaffs():

    staffFullNames =[];
    staffEmail=[];
    staffTitle=[];
    staffDepartment=[];
    staffPwdLastSet=[];
    staffAccountExpiryDate=[];
    staffUsername=[];
    staffPwdExpiryDate=[];
    staffWithExpiryDates=[];
    staffEmailsWithExpiryDates=[];
    staffUsernameWithExpiryDates=[];
    staffCreationDate=[];
    staffLastLogon=[];

    con = db.connect("static/data/database.db")
    cur = con.cursor()

    try: 
        if not con.cursor():
          raise ValueError("Invalid credentials")
        else:
            cur.execute(''' SELECT * FROM STAFF ''')
            results=cur.fetchall();
            for r in results:
                staffFullNames.append(str(r[1]))
                staffUsername.append(str(r[2]))
                staffEmail.append(str(r[3]))
                staffTitle.append(str(r[5]))
                staffDepartment.append(str(r[6]))
                staffCompany.append(str(r[7]))
                staffPwdLastSet.append(str(r[10]))
                staffCreationDate.append(str(r[12]))
                if str(str(r[8]))=="512":
                    staffStatus.append("Enabled")
                elif str(str(r[8]))=="514" or str(str(r[8]))=="65536":
                    staffStatus.append("Disabled")
                elif str(str(r[8]))=="66048":
                    staffStatus.append("Password Never Expires")
                else:
                    staffStatus.append("Unknown")
        con.close()

        for i in range(0,len(staffFullNames)):
            lastDay=date.today()
            if str(staffStatus[i])=="Enabled" and '1601-01-01' not in str(staffPwdLastSet[i]):
              pwdDate=datetime.strptime(str(staffPwdLastSet[i]).split(".")[0],'%Y-%m-%d %H:%M:%S')
              daysTillExpiry=(pwdDate.date() + timedelta(days=90))-lastDay
              if pwdDate.date() + timedelta(days=90) == lastDay:
                  staffPwdExpiryDate.append(pwdDate.date() + timedelta(days=90))
                  staffWithExpiryDates.append(staffFullNames[i])
                  staffUsernameWithExpiryDates.append(staffUsername[i])
                  staffEmailsWithExpiryDates.append(staffEmail[i])
              elif int(str(daysTillExpiry).split(',')[0].split(' ')[0]) < 14 and int(str(daysTillExpiry).split(',')[0].split(' ')[0]) > 0:
                  staffPwdExpiryDate.append(pwdDate.date() + timedelta(days=90))
                  staffWithExpiryDates.append(staffFullNames[i])
                  staffUsernameWithExpiryDates.append(staffUsername[i])
                  staffEmailsWithExpiryDates.append(staffEmail[i])
              
        return staffFullNames,staffDepartment,staffUsername,staffEmail,staffTitle,staffCompany,staffPwdExpiryDate,staffWithExpiryDates,staffEmailsWithExpiryDates,staffStatus,staffCreationDate,staffUsernameWithExpiryDates;
    except core.exceptions.LDAPBindError as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog("Authentication failure: Please make sure you have entered the right credentials")
        raise ValueError(e)
        #print('LDAP Bind Failed: ', e)

    except core.exceptions.LDAPSocketOpenError as ex:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog(ex)
        raise ValueError(ex)

def disabledallStaffs():

    disabledstaffFullNames =[];
    disabledstaffEmail=[];
    disabledstaffTitle=[];
    disabledstaffDepartment=[];
    disabledstaffPwdLastSet=[];
    disabledstaffAccountExpiryDate=[];
    disabledstaffUsername=[];
    disabledstaffCreationDate=[];
    disabledstaffLastLogon=[];
    disabledstaffCompany=[];
    disabledstaffStatus=[];

    con = db.connect("static/data/database.db")
    cur = con.cursor()

    try: 
        if not con.cursor():
          raise ValueError("Invalid credentials")
        else:
            cur.execute(''' SELECT * FROM DISABLED_USERS ''')
            results=cur.fetchall();
            for r in results:
                disabledstaffFullNames.append(str(r[1]))
                disabledstaffUsername.append(str(r[2]))
                disabledstaffEmail.append(str(r[3]))
                disabledstaffTitle.append(str(r[5]))
                disabledstaffDepartment.append(str(r[6]))
                disabledstaffCompany.append(str(r[7]))
                disabledstaffPwdLastSet.append(str(r[10]))
                disabledstaffCreationDate.append(str(r[12]))
                if str(str(r[8]))=="512":
                    disabledstaffStatus.append("Enabled")
                elif str(str(r[8]))=="514" or str(str(r[8]))=="65536":
                    disabledstaffStatus.append("Disabled")
                elif str(str(r[8]))=="66048":
                    disabledstaffStatus.append("Password Never Expires")
                else:
                    disabledstaffStatus.append("Unknown")
        con.close()
        
        return disabledstaffFullNames,disabledstaffDepartment,disabledstaffUsername,disabledstaffEmail,disabledstaffTitle,disabledstaffCompany,disabledstaffStatus,disabledstaffCreationDate;
    except core.exceptions.LDAPBindError as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog("Authentication failure: Please make sure you have entered the right credentials")
        raise ValueError(e)
        #print('LDAP Bind Failed: ', e)

    except core.exceptions.LDAPSocketOpenError as ex:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog(ex)
        raise ValueError(ex)

def loggedUserInfo(username):
        # Create the Server object with the given address.
        server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
        #Create a connection object, and bind with the given DN and password.
        userToSearch = username
        LDAP_USER ="bk\\" + SAusername
        LDAP_PASSWORD = SApassword

        LDAP_FILTER = "(&(objectClass=user)(sAMAccountName="+userToSearch+"))"
        try: 
            conn2 = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
            # Perform a search for a pre-defined criteria.
            # Mention the search filter / filter type and attributes.
            for location in locations:
                membership="OU="+location+",DC=bk,DC=local"
                criteria = "(&(objectClass=user)(sAMAccountName="+userToSearch+"))"
                conn2.search(membership,LDAP_FILTER ,attributes=LDAP_ATTRS)
                # Print the resulting entries.
                for i in conn2.entries:
                    return (str(i.displayName),str(i.title))

        except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            print('LDAP Bind Failed: ', e)


def userCheck(searchUser):
  # Create the Server object with the given address.
    server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
    #Create a connection object, and bind with the given DN and password.
    usermemberOf=[];
    memberOfGroup=[];
    LDAP_USER ="bk\\" + SAusername
    LDAP_PASSWORD = SApassword

    LDAP_FILTER = "(&(objectClass=user)(sAMAccountName="+searchUser+"))"
    try: 
        conn2 = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
        # Perform a search for a pre-defined criteria.
        # Mention the search filter / filter type and attributes.
        membership="DC=bk,DC=local"
        criteria = "(&(objectClass=user)(sAMAccountName="+searchUser+"))"
        conn2.search(membership,LDAP_FILTER ,attributes=LDAP_ATTRS)
        # Print the resulting entries.
        if len(conn2.entries)==0:
          return "false"
        else:
          return "true"
    except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            print('LDAP Bind Failed: ', e)

def userInfo(searchUser):
        # Create the Server object with the given address.
        server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
        #Create a connection object, and bind with the given DN and password.
        usermemberOf=[];
        memberOfGroup=[];
        LDAP_USER ="bk\\" + SAusername
        LDAP_PASSWORD = SApassword

        LDAP_FILTER = "(&(objectClass=user)(sAMAccountName="+searchUser+"))"
        try: 
            conn2 = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
            # Perform a search for a pre-defined criteria.
            # Mention the search filter / filter type and attributes.
            membership="DC=bk,DC=local"
            criteria = "(&(objectClass=user)(sAMAccountName="+searchUser+"))"
            conn2.search(membership,LDAP_FILTER ,attributes=LDAP_ATTRS)
            # Print the resulting entries.
            if len(conn2.entries)==0:
              return "true"
            for i in conn2.entries:
              m=(str(i.memberOf).split('\''))
              userdisplayName=i.displayName
              username=i.sAMAccountName
              email=i.mail
              usertitle=i.title
              userdepartment=i.department
              userAccountControl1=i.userAccountControl
              userPwdLastSet=datetime.strptime(str(i.pwdLastSet).split("+")[0].split(".")[0],'%Y-%m-%d %H:%M:%S')
              pwdExpiryDate=userPwdLastSet.date() + timedelta(days=90)
              userwhenCreated=(str(i.whenCreated)).split('+')[0]
              userwhenChanged=(str(i.whenChanged)).split('+')[0]
              usercompany=i.company
              usermobileNumber=i.mobile
              userDN=i.distinguishedName
              if(str(i.lockoutTime).split("-")[0]=="2021"):
                userlockoutTime="Locked"
              else:
                userlockoutTime="Unlocked"

            for i in range (1,len(m)):
              if (i%2)!=0:
                memberOfGroup.append(m[i].split(',')[0].split('=')[1])

            for member in memberOfGroup:
              usermemberOf.append(member)

            return userdisplayName,username,email,usertitle,userdepartment,userAccountControl1,userwhenCreated,userwhenChanged,usermemberOf,usercompany,userlockoutTime,usermobileNumber,pwdExpiryDate,userDN

        except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            print('LDAP Bind Failed: ', e)

def allGroups():
  # Create the Server object with the given address.
  server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
  LDAP_USER ="bk\\" + SAusername
  LDAP_PASSWORD = SApassword

  LDAP_FILTER = "(&(objectClass=group))"

  allGroupsNames=[];
  allGroupsCreationDate=[];

  try: 
      conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True, authentication='NTLM')
      # Perform a search for a pre-defined criteria.
      # Mention the search filter / filter type and attributes.
      membership="DC=bk,DC=local"
      conn.search(membership, LDAP_FILTER ,attributes=LDAP_ATTRS)
      # Print the resulting entries.
      for i in conn.entries:
        allGroupsNames.append(i.sAMAccountName)
        allGroupsCreationDate.append(i.whenCreated)
      
      return allGroupsNames, allGroupsCreationDate

  except core.exceptions.LDAPBindError as e:
      # If the LDAP bind failed for reasons such as authentication failure.
      print('LDAP Bind Failed: ', e)



def groupMembers(groupToSearch):
    # Create the Server object with the given address.
    server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
    LDAP_USER ="bk\\" + SAusername
    LDAP_PASSWORD = SApassword
    #Create a connection object, and bind with the given DN and password.
    search =groupToSearch
    groupMembersUsername=[];
    groupMembersDisplayname=[];
    groupstaffNames=[];
    staffNames=[];
    LDAP_FILTER = "(&(objectClass=group)(sAMAccountName="+search+"))"
    try: 
        conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True, authentication='NTLM')
        # Perform a search for a pre-defined criteria.
        # Mention the search filter / filter type and attributes.
        membership="DC=bk,DC=local"
        conn.search(membership, LDAP_FILTER ,attributes=LDAP_ATTRS)
        # Print the resulting entries.
        for entry in conn.entries:
            for member in entry.member:
                staffNames.append(member.split(',')[0].split('=')[1])

        for names in staffNames:
            LDAP_FILTER2 = "(&(objectClass=user)(displayname="+names+"))"
            conn.search(membership, LDAP_FILTER2 ,attributes=LDAP_ATTRS)
            for e in conn.entries:
              groupMembersUsername.append(e.sAMAccountName)
              groupMembersDisplayname.append(e.displayname)

        return groupMembersUsername,groupMembersDisplayname

    except core.exceptions.LDAPBindError as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        print('LDAP Bind Failed: ', e)


def getStats():
  # Create the Server object with the given address.
  server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
  #Create a connection object, and bind with the given DN and password.
  LDAP_USER ="bk\\" + SAusername
  LDAP_PASSWORD = SApassword
    
  countbk=0;
  countbkc=0;
  countbkt=0;
  countbki=0;
  activecountbk=0;
  activecountbkc=0;
  activecountbkt=0;
  activecountbki=0;
  disabledcountbk=0;
  disabledcountbkc=0;
  disabledcountbkt=0;
  disabledcountbki=0;
  unknowncountbk=0;
  unknowncountbkc=0;
  unknowncountbkt=0;
  unknowncountbki=0;
  pwdnvrxprcountbk=0;
  pwdnvrxprcountbkc=0;
  pwdnvrxprcountbkt=0;
  pwdnvrxprcountbki=0;

  try: 
    conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD,authentication='NTLM', auto_bind=True)
    # Perform a search for a pre-defined criteria.
    # Mention the search filter / filter type and attributes.
    if not conn.bind():
      raise ValueError("Invalid credentials")
    else:
      for i in range(0,len(staffCompany)):
        if staffCompany[i]=="Bank of Kigali":
            countbk=countbk+1
        if staffCompany[i]=="Bank of Kigali" and str(staffStatus[i])=="Enabled":
            activecountbk=activecountbk+1
        if staffCompany[i]=="Bank of Kigali" and str(staffStatus[i])=="Password Never Expires":
            pwdnvrxprcountbk=pwdnvrxprcountbk+1
        if staffCompany[i]=="Bank of Kigali" and str(staffStatus[i])=="Disabled":
            disabledcountbk=disabledcountbk+1
        if staffCompany[i]=="Bank of Kigali" and str(staffStatus[i])=="Unknown":
            unknowncountbk=unknowncountbk+1  
            
        if staffCompany[i]=="BK Capital":
            countbkc=countbkc+1
        if staffCompany[i]=="BK Capital" and str(staffStatus[i])=="Enabled":
            activecountbkc=activecountbkc+1
        if staffCompany[i]=="BK Capital" and str(staffStatus[i])=="Password Never Expires":
            pwdnvrxprcountbkc=pwdnvrxprcountbkc+1
        if staffCompany[i]=="BK Capital" and str(staffStatus[i])=="Disabled":
            disabledcountbkc=disabledcountbkc+1
        if staffCompany[i]=="BK Capital" and str(staffStatus[i])=="Unknown":
            unknowncountbkc=unknowncountbkc+1

        if staffCompany[i]=="BK Tech House":
            countbkt=countbkt+1
        if staffCompany[i]=="BK Tech House" and str(staffStatus[i])=="Enabled":
            activecountbkt=activecountbkt+1
        if staffCompany[i]=="BK Tech House" and str(staffStatus[i])=="Password Never Expires":
            pwdnvrxprcountbkt=pwdnvrxprcountbkt+1
        if staffCompany[i]=="BK Tech House" and str(staffStatus[i])=="Disabled":
            disabledcountbkt=disabledcountbkt+1
        if staffCompany[i]=="BK Tech House" and str(staffStatus[i])=="Unknown":
            unknowncountbkt=unknowncountbkt+1

        if staffCompany[i]=="BK Insurance":
            countbki=countbki+1
        if staffCompany[i]=="BK Insurance" and str(staffStatus[i])=="Enabled":
            activecountbki=activecountbki+1
        if staffCompany[i]=="BK Insurance" and str(staffStatus[i])=="Password Never Expires":
            pwdnvrxprcountbki=pwdnvrxprcountbki+1
        if staffCompany[i]=="BK Insurance" and str(staffStatus[i])=="Disabled":
            disabledcountbki=disabledcountbki+1
        if staffCompany[i]=="BK Insurance" and str(staffStatus[i])=="Unknown":
            unknowncountbki=unknowncountbki+1

    return countbk,activecountbk,disabledcountbk,unknowncountbk,pwdnvrxprcountbk,countbkc,activecountbkc,disabledcountbkc,unknowncountbkc,pwdnvrxprcountbkc,countbkt,activecountbkt,disabledcountbkt,unknowncountbkt,pwdnvrxprcountbkt,countbki,activecountbki,disabledcountbki,unknowncountbki,pwdnvrxprcountbki
  except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            errorLog("Authentication failure: Please make sure you have entered the right credentials")
            raise ValueError(e)
            #print('LDAP Bind Failed: ', e)

  except core.exceptions.LDAPSocketOpenError as ex:
      # If the LDAP bind failed for reasons such as authentication failure.
      errorLog(ex)
      raise ValueError(ex)

def resetpassword(resetuser,newpassword):
    newuserpassword=newpassword
    # Create the Server object with the given address.    
    LDAP_USER ="bk\\" + SAusername
    LDAP_PASSWORD = SApassword
    server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
    try: 
        conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
        # Perform a search for a pre-defined criteria.
        # Mention the search filter / filter type and attributes.
        for location in locations:
            membership="OU="+location+",DC=bk,DC=local"
            LDAP_FILTER = "(&(objectClass=user)(sAMAccountName="+resetuser+"))"
            conn.search(membership, LDAP_FILTER ,attributes=LDAP_ATTRS)
            # Print the resulting entries.
            for i in conn.entries:
                if str(i.userAccountControl)=="514" or str(i.userAccountControl)=="66050":
                  return "Account Disabled"
                else:
                    conn.extend.microsoft.modify_password(str(i.distinguishedName), newuserpassword)
                    return "Password Restet succesfully"
    except core.exceptions.LDAPBindError as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog("Authentication failure: Please make sure you have entered the right credentials")
        raise ValueError(e)
            #print('LDAP Bind Failed: ', e)

    except core.exceptions.LDAPSocketOpenError as ex:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog(ex)
        raise ValueError(ex)



def lockedUsers():
  lockedUserUsername=[]
  lockedUserFullname=[]
  lockedUserLockoutTime=[]
  server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
  LDAP_USER ="bk\\" + SAusername
  LDAP_PASSWORD = SApassword
  #Create a connection object, and bind with the given DN and password.
  LDAP_FILTER = "(&(objectClass=user))"
  try: 
      conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True, authentication='NTLM')
      # Perform a search for a pre-defined criteria.
      # Mention the search filter / filter type and attributes.
      for location in locations:
          membership="OU="+location+",DC=bk,DC=local"
          conn.search(membership, LDAP_FILTER ,attributes=LDAP_ATTRS)
          # Print the resulting entries.
          for i in conn.entries:
              if(str(i.lockoutTime).split("-")[0]=="2021"):
                lockedUserUsername.append(str(i.sAMAccountName))
                lockedUserFullname.append(str(i.displayName))
                lockedUserLockoutTime.append(str(i.lockoutTime).split('.')[0])

      return lockedUserFullname,lockedUserUsername,lockedUserLockoutTime

  except core.exceptions.LDAPBindError as e:
      # If the LDAP bind failed for reasons such as authentication failure.
      print('LDAP Bind Failed: ', e)

def usertounlock(userunlock):
  server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
  LDAP_USER ="bk\\" + SAusername
  LDAP_PASSWORD = SApassword
  #Create a connection object, and bind with the given DN and password.
  LDAP_FILTER = "(&(objectClass=user)(sAMAccountName="+userunlock+"))"
  try: 
      conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True, authentication='NTLM')
      # Perform a search for a pre-defined criteria.
      # Mention the search filter / filter type and attributes.
      for location in locations:
          membership="OU="+location+",DC=bk,DC=local"
          conn.search(membership, LDAP_FILTER ,attributes=LDAP_ATTRS)
          # Print the resulting entries.
          for i in conn.entries:
              if(str(i.lockoutTime).split("-")[0]=="2021"):
                  conn.extend.microsoft.unlock_account(str(i.distinguishedName))
  except core.exceptions.LDAPBindError as e:
      # If the LDAP bind failed for reasons such as authentication failure.
      print('LDAP Bind Failed: ', e)

def disableUser(searchUser):
        # Create the Server object with the given address.
        server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
        LDAP_USER="bk\\"+ SAusername
        LDAP_PASSWORD= SApassword

        LDAP_FILTER = "(&(objectClass=user)(sAMAccountName="+searchUser+"))"
        try: 
            conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True, authentication='NTLM')
            # Perform a search for a pre-defined criteria.
            # Mention the search filter / filter type and attributes.
            membership="DC=bk,DC=local"
            conn.search(membership, LDAP_FILTER ,attributes=LDAP_ATTRS)
            # Print the resulting entries.
            for i in conn.entries:
                if str(i.userAccountControl)=="512":
                    #response = input("User:" + str(i.sAMAccountName) + " is enabled, Do you want to disable him?(Enter Yes to confirm)")
                    #if (response=="yes" or response=="Yes" or response=="YES" or response=="Y" or response=="y"):
                  conn.modify(str(i.distinguishedName), {'userAccountControl': [('MODIFY_REPLACE', 514)]})
                  results1=conn.modify_dn(str(i.distinguishedName), str(i.distinguishedName).split(",")[0] , new_superior='OU=DISABLED USERS,DC=bk,DC=local')
                  print(results1)
                  m=(str(i.memberOf).split('\''))

                  for j in range (1,len(m)):
                    if (j%2)!=0:
                        conn.extend.microsoft.remove_members_from_groups(str(i.distinguishedName),str(m[j]))
                  return "Disabled"
                elif str(i.userAccountControl)=="514":
                  conn.modify(str(i.distinguishedName), {'userAccountControl': [('MODIFY_REPLACE', 512)]})
                  return "Enabled"

        except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            print('LDAP Bind Failed: ', e)

def removefromgroup(searchUser,sgname):
    # Create the Server object with the given address.
    server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
    #Create a connection object, and bind with the given DN and password.
    groupsName=''
    groupsdn=[]
    userToSearch =searchUser
    LDAP_USER="bk\\"+ SAusername
    LDAP_PASSWORD= SApassword
    LDAP_FILTER = "(&(objectClass=user)(sAMAccountName ="+userToSearch+"))"
    LDAP_FILTER2 ="(&(objectclass=group)(sAMAccountName ="+sgname+"))"
    user_dn=""
    try: 
        conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
        # Perform a search for a pre-defined criteria.
        # Mention the search filter / filter type and attributes.
        for location in locations:
            membership="OU="+location+",DC=bk,DC=local"
            conn.search(membership, LDAP_FILTER ,attributes=LDAP_ATTRS)
            # Print the resulting entries.
            for i in conn.entries:
                user_dn=str(i.distinguishedName)

        conn.search("DC=bk,DC=local", LDAP_FILTER2 , attributes=LDAP_ATTRS)
        # Print the resulting entries.
        for i in conn.entries:
            group_dn=str(i.distinguishedName)
            results=conn.extend.microsoft.remove_members_from_groups(user_dn, group_dn)
            if results:
                return "Success"
            else:
                return "Failed"
            
        activityLog(username,"006",userToSearch)

    except core.exceptions.LDAPBindError as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        print('LDAP Bind Failed: ')
    except core.exceptions.LDAPSocketOpenError as ex:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog(ex)
        print('LDAP Bind Failed')


def ITusers():
    # Create the Server object with the given address.
    server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
    #Create a connection object, and bind with the given DN and password.
    LDAP_USER ="bk\\" + SAusername
    LDAP_PASSWORD = SApassword

    LDAP_FILTER = "(&(objectClass=user))"
    try: 
        conn2 = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
        # Perform a search for a pre-defined criteria.
        # Mention the search filter / filter type and attributes.
        membership="OU=ICT,OU=BKSIEGE,OU=KIGALI,DC=bk,DC=local"
        conn2.search(membership,LDAP_FILTER ,attributes=LDAP_ATTRS)
        # Print the resulting entries.
        ICTusers=[]
        ICTusernames=[]
        for i in conn2.entries:
          ICTusers.append(i.displayName)
          ICTusernames.append(i.sAMAccountName)
            
        return ICTusers,ICTusernames

    except core.exceptions.LDAPBindError as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        print('LDAP Bind Failed: ', e)


def usersPerYear():
    year2013StaffCount=0;
    year2014StaffCount=0;
    year2015StaffCount=0;
    year2016StaffCount=0;
    year2017StaffCount=0;
    year2018StaffCount=0;
    year2019StaffCount=0;
    year2020StaffCount=0;
    year2021StaffCount=0;
    server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
    #Create a connection object, and bind with the given DN and password.
    LDAP_USER="bk\\"+ SAusername
    LDAP_PASSWORD= SApassword
    LDAP_FILTER = "(&(objectClass=user))"
    try: 
        conn = Connection(server, LDAP_USER, LDAP_PASSWORD, auto_bind=True,authentication='NTLM')
        # Perform a search for a pre-defined criteria.
        # Mention the search filter / filter type and attributes.
        if not conn.bind():
            raise ValueError("Invalid credentials")
        else:
            for location in locations:
                membership="OU="+location+",DC=bk,DC=local"
                conn.search(membership, LDAP_FILTER , attributes=LDAP_ATTRS)
                # Print the resulting entries.
                for i in conn.entries:
                    #userList.append([str(i.sAMAccountName),int(str(i.LogonCount)),str(i.whenCreated)])
                    #print (str(i.sAMAccountName) +" "+str(i.LogonCount))
                    if int(str(i.whenCreated).split('-')[0])==2013:
                        year2013StaffCount=year2013StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2014:
                        year2014StaffCount=year2014StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2015:
                        year2015StaffCount=year2015StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2016:
                        year2016StaffCount=year2016StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2017:
                        year2017StaffCount=year2017StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2018:
                        year2018StaffCount=year2018StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2019:
                        year2019StaffCount=year2019StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2020:
                        year2020StaffCount=year2020StaffCount+1
                    elif int(str(i.whenCreated).split('-')[0])==2021:
                        year2021StaffCount=year2021StaffCount+1
        return(year2013StaffCount,year2014StaffCount,year2015StaffCount,year2016StaffCount,year2017StaffCount,year2018StaffCount,year2019StaffCount,year2020StaffCount,year2021StaffCount)
        
    except core.exceptions.LDAPBindError as e:
            # If the LDAP bind failed for reasons such as authentication failure.
            errorLog("Authentication failure: Please make sure you have entered the right credentials")
            print ('Authentication failure: Please make sure you have entered the right credentials')
            #print('LDAP Bind Failed: ', e)

    except core.exceptions.LDAPSocketOpenError as ex:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog(ex)
        print('LDAP Bind Failed: ', ex)
