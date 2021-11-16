import json

data={}
data['config']=[]
data['config'].append({
    'ldapserver1':'10.102.148.3',
    'ldapserver2':'10.103.148.3',
    'domain':'bk.local',
    'smtpserver':'smtp.office365.com',
    'port':'587',
    'securityprotocol':'tls',
    'email': 'crugamba@bk.rw',
    'password':'@Rcedou@2391!'
})

with open('./static/data/config.txt','w') as outfile:
    json.dump(data,outfile)