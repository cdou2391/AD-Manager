import sqlite3 as db
from ldap3 import Server, Connection, ObjectDef, AttrDef, Reader, Writer, ALL, core
from models import groupMembers,appServiceAccount
import sys
import logging
from logging.handlers import RotatingFileHandler
from datetime import date,datetime,timedelta
import json
from datetime import date,datetime,timedelta


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

usernameSA,passwordSA=appServiceAccount()
def syncAllStaff():
    # Create the Server object with the given address.
    con = db.connect("/home/crugamba/SimpleADManager/static/data/database.db")
    cur = con.cursor()


    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='STAFF' ''')

    #if the count is 1, then table exists
    if cur.fetchone()[0]==1 : {
        print('Table STAFF exists.')
    }
    else:{
        con.execute('''CREATE TABLE STAFF
                    ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text, 
                    [Email] text,[Mobile] text,[Title] text,[Department] text,[Company] text,[Account_Status] integer,[Account_State] integer,
                    [Password_Last_Set] date,[Password_Expiry_Date] date,[Date_Created] date,[Last_Logon] date,[Groups] text)''')
    }

    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='SERVICE_ACCOUNT' ''')

    if cur.fetchone()[0]==1 : {
        print('Table SERVICE_ACCOUNT exists.')
    }
    else:{
        con.execute('''CREATE TABLE SERVICE_ACCOUNT
                ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text,
                [Description] text,[Account_Status] text,[Date_Created] text,[Last_Logon] date)''')
    }

    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='CONSULTANTS' ''')
    if cur.fetchone()[0]==1 : {
        print('Table CONSULTANTS exists.')
    }
    else:{
        con.execute('''CREATE TABLE CONSULTANTS
                ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text,
                [Description] text,[Account_Status] text,[Date_Created] text,[Last_Logon] date)''')
    }

    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='DISABLED_USERS' ''')
    if cur.fetchone()[0]==1 : {
        print('Table DISABLED_USERS exists.')
    }
    else:{
        con.execute('''CREATE TABLE DISABLED_USERS
                    ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text, 
                    [Email] text,[Mobile] text,[Title] text,[Department] text,[Company] text,[Account_Status] integer,[Account_State] integer,
                    [Password_Last_Set] date,[Password_Expiry_Date] date,[Date_Created] date,[Last_Logon] date,[Groups] text)''')
    }

    

    #groupMembersUsername=[];
    #groupMembersDisplayname=[];
    cur.execute(''' SELECT count(name) FROM sqlite_master WHERE type='table' AND name='USERS' ''')
    if cur.fetchone()[0]==1:
        print('Table USERS exists.')
    else:
        cur.execute('''CREATE TABLE USERS
                ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text,
                [title] text,  [Rights] text,[Date_Added] text,[Last_Logon] text,[Status] text)''')
    

    LDAP_USER ="bk\\" + usernameSA
    LDAP_PASSWORD =passwordSA
    LDAP_SERVER="10.102.148.3"
    server = Server(LDAP_SERVER, get_info=ALL,use_ssl=True)
    #Create a connection object, and bind with the given DN and password.
    staffFullNames =[];
    staffEmail=[];
    staffTitle=[];
    staffMobile=[];
    staffDepartment=[];
    staffPwdLastSet=[];
    staffAccountExpiryDate=[];
    staffUsername=[];
    staffCompany=[];
    staffStatus=[];
    staffState=[];
    staffPwdExpiryDate=[];
    staffWithExpiryDates=[];
    staffEmailsWithExpiryDates=[];
    staffUsernameWithExpiryDates=[];
    staffCreationDate=[];
    staffGroups=[];
    staffLastLogon=[];
    staffDN=[];

    
    disabledstaffFullNames =[];
    disabledstaffEmail=[];
    disabledstaffTitle=[];
    disabledstaffMobile=[];
    disabledstaffDepartment=[];
    disabledstaffPwdLastSet=[];
    disabledstaffAccountExpiryDate=[];
    disabledstaffUsername=[];
    disabledstaffCompany=[];
    disabledstaffStatus=[];
    disabledstaffState=[];
    disabledstaffPwdExpiryDate=[];
    disabledstaffWithExpiryDates=[];
    disabledstaffEmailsWithExpiryDates=[];
    disabledstaffUsernameWithExpiryDates=[];
    disabledstaffCreationDate=[];
    disabledstaffGroups=[];
    disabledstaffLastLogon=[];

    serviceAccountNames=[];
    serviceAccountCreationDate=[];
    serviceAccountStatus=[];
    serviceAccountDescription=[];
    serviceAccountUsername=[];
    serviceAccountLastLogon=[];

    consultantName=[];
    consultantCreationDate=[];
    consultantStatus=[];
    consultantDescription=[];
    consultantUsername=[];
    consultantLastLogon=[];


    itusername=[];
    itfullnames=[];
    itpost=[];

    try: 
        conn = Connection(server, user=LDAP_USER, password=LDAP_PASSWORD,authentication='NTLM', auto_bind=True)
        # Perform a search for a pre-defined criteria.
        # Mention the search filter / filter type and attributes.
        if not conn.bind():
            raise ValueError("Invalid credentials")
        else:

            membership="OU=Consultants,OU=BKSIEGE,OU=KIGALI,DC=bk,DC=local"
            conn.search(membership, LDAP_FILTER_USER ,attributes=LDAP_ATTRS)
            for i in conn.entries:
                consultantName.append(i.displayName)
                consultantCreationDate.append(i.whenCreated)
                consultantDescription.append(i.description)
                consultantUsername.append(i.sAMAccountName)
                consultantLastLogon.append(i.lastLogon)
                if str(i.userAccountControl)=="512":
                    consultantStatus.append("Enabled")
                elif str(i.userAccountControl)=="514" or str(i.userAccountControl)=="65536":
                    consultantStatus.append("Disabled")
                elif str(i.userAccountControl)=="66048":
                    consultantStatus.append("Password Never Expires")
                else:
                    consultantStatus.append("Unknown")

            rowsQuery = "SELECT Count() FROM CONSULTANTS"
            cur.execute(rowsQuery)
            ConcountDB = cur.fetchone()[0]
            ConcountAD=len(consultantName)
            print("Droping CONSULTANTS table.....")
            con.execute("DROP TABLE CONSULTANTS")
            print("Re-creating CONSULTANTS table.....")
            con.execute('''CREATE TABLE CONSULTANTS
                ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text,
                [Description] text,[Account_Status] text,[Date_Created] text,[Last_Logon] date)''')
            print("Inserting new data into CONSULTANTS table.....")
            for i in range (0, len(consultantName)):
                con.execute('''INSERT INTO CONSULTANTS (Fullnames,Username,Description,Account_Status,Date_Created,Last_Logon)  
                                VALUES (?,?,?,?,?,?)''',(str(consultantName[i]),str(consultantUsername[i]),
                                                        str(consultantDescription[i]),str(consultantStatus[i]),
                                                        str(consultantCreationDate[i]),str(consultantLastLogon[i])))
            
            membership="OU=DISABLED USERS,DC=bk,DC=local"
            conn.search(membership,LDAP_FILTER_USER , attributes=LDAP_ATTRS)
            # Print the resulting entries.
            for i in conn.entries:
                disabledstaffFullNames.append(i.displayName)
                disabledstaffUsername.append(i.sAMAccountName)
                disabledstaffEmail.append(i.mail)
                disabledstaffMobile.append(i.mobile)
                disabledstaffTitle.append(i.title)
                disabledstaffDepartment.append(i.department)
                disabledstaffCompany.append(i.company)
                disabledstaffStatus.append(i.userAccountControl)
                disabledstaffState.append(i.lockoutTime)
                disabledstaffPwdLastSet.append(i.pwdLastSet)
                disabledstaffCreationDate.append(i.whenCreated)
                disabledstaffGroups.append(i.memberOf)
                disabledstaffLastLogon.append(i.lastLogon)

                disabledlastDay=date.today()
                disabledpwdDate=datetime.strptime(str(i.pwdLastSet).split(".")[0].split("+")[0],'%Y-%m-%d %H:%M:%S')
                disableddaysTillExpiry=(disabledpwdDate.date() + timedelta(days=90))-disabledlastDay
                disabledpwdExpiryDate=str(disabledpwdDate.date() + timedelta(days=90))


                    
            rowsQuery = "SELECT Count() FROM DISABLED_USERS"
            cur.execute(rowsQuery)
            disabledstaffCountDB=cur.fetchone()[0]

            disabledstaffCountAD=len(disabledstaffFullNames)
            print("Droping DISABLED_USERS table.....")
            con.execute("DROP TABLE DISABLED_USERS")
            print("Re-creating DISABLED_USERS table.....")
            con.execute('''CREATE TABLE DISABLED_USERS
                    ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text, 
                    [Email] text,[Mobile] text,[Title] text,[Department] text,[Company] text,[Account_Status] integer,[Account_State] integer,
                    [Password_Last_Set] date,[Password_Expiry_Date] date,[Date_Created] date,[Last_Logon] date,[Groups] text)''')
            print("Inserting new data into DISABLED_USERS table.....")
            for i in range (0, len(disabledstaffFullNames)):
                con.execute('''INSERT INTO DISABLED_USERS (Fullnames,Username,Email,Mobile,Title,Department,
                                                Company,Account_Status,Account_State,Password_Last_Set,
                                                Password_Expiry_Date,Date_Created,Last_Logon,Groups)  
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(str(disabledstaffFullNames[i]),str(disabledstaffUsername[i]),str(disabledstaffEmail[i]),
                                                                str(disabledstaffMobile[i]),str(disabledstaffTitle[i]),str(disabledstaffDepartment[i]),
                                                                str(disabledstaffCompany[i]),str(disabledstaffStatus[i]),str(disabledstaffState[i]),
                                                                str(disabledstaffPwdLastSet[i]),str(disabledpwdExpiryDate),str(disabledstaffCreationDate[i]),
                                                                str(disabledstaffLastLogon[i]),str(disabledstaffGroups[i])))


            membership="OU=Service Accounts,DC=bk,DC=local"
            conn.search(membership, LDAP_FILTER_USER ,attributes=LDAP_ATTRS)
            for i in conn.entries:
                serviceAccountNames.append(i.displayName)
                serviceAccountCreationDate.append(i.whenCreated)
                serviceAccountStatus.append(i.userAccountControl)
                serviceAccountDescription.append(i.description)
                serviceAccountUsername.append(i.sAMAccountName)
                serviceAccountLastLogon.append(i.lastLogon)

            rowsQuery = "SELECT Count() FROM SERVICE_ACCOUNT"
            cur.execute(rowsQuery)
            SAcountDB = cur.fetchone()[0]
            SAcountAD=len(serviceAccountNames)
            print("Droping SERVIVE_ACCOUNT table.....")
            con.execute("DROP TABLE SERVICE_ACCOUNT")
            print("Re-creating SERVIVE_ACCOUNT table.....")
            con.execute('''CREATE TABLE SERVICE_ACCOUNT
                ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text,
                [Description] text,[Account_Status] text,[Date_Created] text,[Last_Logon] date)''')
            print("Inserting new data into SERVIVE_ACCOUNT table.....")
            for i in range (0, len(serviceAccountNames)):
                con.execute('''INSERT INTO SERVICE_ACCOUNT (Fullnames,Username,Description,Account_Status,Date_Created,Last_Logon)  
                                VALUES (?,?,?,?,?,?)''',(str(serviceAccountNames[i]),str(serviceAccountUsername[i]),
                                                        str(serviceAccountDescription[i]),str(serviceAccountStatus[i]),
                                                        str(serviceAccountCreationDate[i]),str(serviceAccountLastLogon[i])))
            
            membership="OU=ICT,OU=BKSIEGE,OU=KIGALI,DC=bk,DC=local"
            conn.search(membership, LDAP_FILTER_USER ,attributes=LDAP_ATTRS)
            for i in conn.entries:
                itfullnames.append(i.displayName)
                itusername.append(i.sAMAccountName)
                itpost.append(i.title)
            rowsQuery = "SELECT Count() FROM USERS"
            cur.execute(rowsQuery)
            ITcountDB = cur.fetchone()[0]
            ITcountAD=len(itusername)
            print("Droping USERS table.....")
            con.execute("DROP TABLE USERS")
            print("Re-creating USERS table.....")
            con.execute('''CREATE TABLE USERS
                ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text,
                [title] text,  [Rights] text,[Date_Added] text,[Last_Logon] text,[Status] text)''')
            print("Inserting new data into USERS table.....")
            for i in range (0, len(itfullnames)):
                    con.execute('''INSERT INTO USERS (Fullnames,Username,title,Rights,Date_Added,Last_Logon,Status)  
                                    VALUES (?,?,?,?,?,?,?)''',(str(itfullnames[i]),str(itusername[i]),str(itpost[i]),
                                                            "No Access", "2021-04-25","Never","Disabled"))
            
            cur.execute('''UPDATE USERS SET STATUS = ? WHERE USERNAME = ? ;''',("Enabled","crugamba",))
            cur.execute('''UPDATE USERS SET RIGHTS = ? WHERE USERNAME = ? ;''',("Full Access","crugamba",))

            for location in locations:
                membership="OU="+location+",DC=bk,DC=local"
                conn.search(membership,LDAP_FILTER_USER , attributes=LDAP_ATTRS)
                # Print the resulting entries.
                for i in conn.entries:
                    staffDN.append(i.distinguishedName)
                    staffFullNames.append(i.displayName)
                    staffUsername.append(i.sAMAccountName)
                    staffEmail.append(i.mail)
                    staffMobile.append(i.mobile)
                    staffTitle.append(i.title)
                    staffDepartment.append(i.department)
                    staffCompany.append(i.company)
                    staffStatus.append(i.userAccountControl)
                    staffState.append(i.lockoutTime)
                    staffPwdLastSet.append(i.pwdLastSet)
                    staffCreationDate.append(i.whenCreated)
                    staffGroups.append(i.memberOf)
                    staffLastLogon.append(i.lastLogon)

                    lastDay=date.today()
                    pwdDate=datetime.strptime(str(i.pwdLastSet).split(".")[0].split("+")[0],'%Y-%m-%d %H:%M:%S')
                    daysTillExpiry=(pwdDate.date() + timedelta(days=90))-lastDay
                    pwdExpiryDate=str(pwdDate.date() + timedelta(days=90))


                    
            rowsQuery = "SELECT Count() FROM STAFF"
            cur.execute(rowsQuery)
            staffCountDB=cur.fetchone()[0]

            staffCountAD=len(staffFullNames)
            print("Droping STAFF table.....")
            con.execute("DROP TABLE STAFF")
            print("Re-creating STAFF table.....")
            
            con.execute('''CREATE TABLE STAFF
                    ([generated_id] INTEGER PRIMARY KEY,[Fullnames] text, [Username] text, 
                    [Email] text,[Mobile] text,[Title] text,[Department] text,[Company] text,[Account_Status] integer,[Account_State] integer,
                    [Password_Last_Set] date,[Password_Expiry_Date] date,[Date_Created] date,[Last_Logon] date,[Groups] text)''')
            print("Inserting new data into STAFF table.....")

            
            for i in range (0, len(staffFullNames)):
                if "Consultants" not in str(staffDN[i]):
                    con.execute('''INSERT INTO STAFF (Fullnames,Username,Email,Mobile,Title,Department,
                                                    Company,Account_Status,Account_State,Password_Last_Set,
                                                    Password_Expiry_Date,Date_Created,Last_Logon,Groups)  
                                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',(str(staffFullNames[i]),str(staffUsername[i]),str(staffEmail[i]),
                                                                    str(staffMobile[i]),str(staffTitle[i]),str(staffDepartment[i]),
                                                                    str(staffCompany[i]),str(staffStatus[i]),str(staffState[i]),
                                                                    str(staffPwdLastSet[i]),str(pwdExpiryDate),str(staffCreationDate[i]),
                                                                    str(staffLastLogon[i]),str(staffGroups[i])))
            con.commit()
            synStat,synTime= importStatus()
            return cur.lastrowid,synStat,synTime
        
    except core.exceptions.LDAPBindError as e:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog("Authentication failure: Please make sure you have entered the right credentials")
        raise ValueError(e)
        #print('LDAP Bind Failed: ', e)

    except core.exceptions.LDAPSocketOpenError as ex:
        # If the LDAP bind failed for reasons such as authentication failure.
        errorLog(ex)
        raise ValueError(ex)

def importStatus():
    syncStatus=[];
    syncTime=[];

    syncStatus.append("Success")
    syncTime.append(datetime.now())
    print("Sync Status: "  + syncStatus[0] + " done at " + str(syncTime[0]).split(".")[0])
    return syncStatus[0],str(syncTime[0]).split(".")[0]


if __name__ == '__main__':
    inArg=sys.argv
    #searchUser(sys.argv[1],sys.argv[2],sys.argv[3])
    syncAllStaff()
          