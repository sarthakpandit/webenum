#!/usr/bin/env python
# -*- coding: utf-8 -*-

# -------------------------------------------------------
#
# This code is released under the GNU / GPL v3
# You are free to use, edit and redistribuite it 
# under the terms of the GNU / GPL license.
# -------------------------------------------------------

import getopt, sys, urllib, urllib2, random, re, itertools, cookielib, urlparse, string

w_default = ["about","access","accesso", "accessi", "accounting", "account","accounts","accnt","adkit","admin", "adminlogin", "administracion","administrador","administrator","administrators","admins", "amministratore", "amministratori", "ads","affiliate","affiliates","afiliados", "affiliati", "agenda","agent","ajax","akamai","alerts","alpha","analyzer","announce","announcements","antivirus","apache","app","application","applications", "applicazioni", "apps","articolo", "articoli", "articles", "article", "auction","auth", "authenticate", "authentication", "autenticazione", "auto","av","b","back","backend","backup","banking","beta","billing","biz","blog","blogs","broadcast","bug","bugs","bugzilla","build","bulletins","buy","cache","calendar","careers","carrello", "carrelli","catalog","catalogo","cc", "carta", "carte", "cert","certificates", "certificato", "certificati","certify","certserv","certsrv","cgi","channel","channels","chat","chats","check","checkpoint","cisco","class","classes","classifieds","classroom","client", "cliente", "clienti", "clientes","clients","club","clubs","cluster","clusters","cmail","cms", "cms_users", "cms_passwords", "cms_accounts", "cms_admins", "cms_user", "cms_password", "cms_account", "cms_admin", "code","coldfusion","commerce","commerceserver","community","compras","concentrator","conference","conferencing","confidential","configuration", "configurazione", "config", "conf", "cfg", "connect","console","consult","consultant","consultants","consulting","consumer","contact", "contacts", "contatti", "content","contracts","core","corp","corpmail","corporate","correo","correoweb","courses","crm","css","customer","customers","cv","cvs","d","data", "dates","database01","database02","database1","database2","databases","datastore","datos","dati", "db","db0","db01","db02","db1","db2","dealers","def","default","delta","demo","demonstration","demos", "dimostrazione", "depot","design","designer","dev","devel","develop","developer","developers","development","device","devserver","devsql","dhcp","dial","dialup","digital","dir","direct","directory", "directories", "disc","discovery","discuss","discussion","discussions","disk", "disks", "distributer","distributers","dmail", "dnews","dns","do","docs","documentos","documents", "documentation", "documenti", "documento", "domain","domains","dominio","download","downloads","drupal","dyn","dynamic","e","e-com","e-commerce","echo","ecom","ecommerce","edu","ejemplo","esempio","email", "emails", "e-mail", "e-mails","employees","empresa","empresas","enable","eng","engine","engineer","engineering","enterprise","epsilon","estadisticas","esx","et","eta","europe","events","domain","exchange","extern","external","extranet","f","fax","feedback","feeds","field","file","files","fileserv","fileserver","filter","find","fix","fixes","flash","foobar","forum","forums","foto","fotos","foundry","freeware", "front","ftp","fw","galleria","galeria","galleries","gallery","games","gamma","gateway","gm","gmail","groups","guest","gw", "hash",  "hashes", "hello","help","helpdesk","helponline","hi","hidden","home","homes","host","hosts","hotel","howto","http","https","hub","humanresources","i","ids","iis","images","imail","img", "imgs","immagini", "image", "inc","include","incoming", "incomings", "info","inside","install","intern", "interno", "internal","international","internet","intl","intranet","invalid","investor","investors","invia","invio", "inviato", "inviati","io", "iscritto", "iscritti","jobs","job","kerberos","keynote","l","lab","laboratory","labs","lambda","lan","laptop","launch","ldap","legal","li","lib","library","link","lista", "liste", "lists", "list","live","load","local","localhost","log","log0","log1","log2","logfile","logfiles","logger","logging","loghost","login", "logins", "log-in", "logs", "logout", "loginout", "lotus","mac","master", "masters","mail","mailer","mailing","maillist","maillists","mailroom","mailserv","mailsite","mails","main","maint","mall","manage","management","manager","manufacturing","map","maps","marketing","marketplace","media", "medias", "member","members", "memberid", "members_id", "membri", "membro", "messages", "messaggi", "messaggio", "messenger","mirror","monitor","movies","mp3","mpeg","mpg","ms","msg", "msgs", "ms-exchange","ms-sql","msexchange","mssql","mssql0","mssql1","msysobject","multimedia","music","my","mysql","mysql0","mysql1","name","names", "nomi", "nome", "nat","net","netapp","netdata","netstats","network","new","news","novita", "notizia", "notizie", "newsfeed","newsfeeds","newsgroups","no","node","nomi", "nome", "noticias","null","office","offices","ok","old","online","open","operations","oracle","orders","out","outbound","outgoing","outlook","outside","p","page","pager","pages","pagine","pagina", "password", "pass", "pass_hash", "passw", "pword", "pwrd", "pwd", "pwds", "pw", "passes", "passwords", "partner","partners","patch","patches","pbx","pcmail", "personal", "personale","pgp","phi","phone","phones", "photos","pics","pictures", "pix","policy", "policies", "polls","pop","portal","portals","portfolio","post", "posts","posta","posta1","posta2","postoffice","press","printer","priv","privacy","private","privato","problems", "products", "prodotto", "prodotti","profiles", "profili", "profilo", "project","projects", "progetti", "progetto", "promo","proxy","prueba","prova","prove", "prova1", "prova2","pub","public","pubs","pubblico", "pubblici","pw","py","q","qmail","r","radius","read", "ricevuto", "ricevuti","ref","reference","reg","register","registro","registri","registry","regs","relay","rem","remote","reports","research","ricerca", "ricerche","reseller","reserved","resumenes","root","route","rs","rss","rw","s","s1","sadmin","safe","sales","scanner","schedules","sd","se","search", "searches", "sec","secret","secure","secured", "securid","security","sendmail","serv", "server","server1","servers","service","services", "servicio","servidor","setup", "settings", "setting", "shared","sharepoint","shareware","shipping","shop","shops","shoppers","shopping","sigma","sign","signin","signup","site","sms","smtp","snort","socal","soci", "socio","software","solutions","source","sourcecode","sources", "spam","sql","sqlserver","squid","ss","ssh","ssl","staff","stage","staging","start","stat","static","statistics","stats","stock","storage","store", "store1", "store2", "streaming","studio","submit","submission", "submissions", "subversion","sun","supplier","suppliers","support","sw","sysadmin", "sysadmins", "sysadm", "sysback","syslog","syslogs", "sysobjects", "system", "systems", "teams", "team","tech","techsupport","telephone","telephones","telephony","temp","temp1", "temp2", "terminal","testbed","testing","test","tests","testo","testserver","testsite","testsql","times","to", "todo","tool","tools","tracker","training","transfers", "trasferimenti","tumb","thumbnails", "thumbnail","tunnel","tv","updates","upload","uploads", "usr", "usrs", "usr1", "usr2", "user", "user1", "user2", "users","usuarios", "usuario", "utente", "utenti", "username", "user_name", "user_username", "uname", "usern", "user_password", "user_pass", "user_passw", "user_pwrd", "user_pwd", "user_id", "user_ids", "user_user", "user_users", "user_log","user_logs", "utilities","vend","vendors","venditori","video","videos","vm","vnc","voice","voicemail","voip","vpn","w", "wais","wallet","wap","w3c","web","webaccess","webadmin","webalizer","webboard","webcache","webcam","webcast","webdev","webdocs","webfarm","webhelp","weblib","weblogic","webmail","webmaster","webproxy","webs","webserv","webserver","webservices","website","websites","websphere","websrv","webstats","webstore","websvr","webtrends","welcome","whois","wiki","win","wlan","wordpress","work", "works","world","write","webserver", "ws","wusage","wv","ww","www","www-1", "www01", "www1","www2","www3","wwwdev","wwwmail","xmail","xml", "zone", "zones", "articoli"]

version = "WebEnum 0.1 (https://code.google.com/p/webenum/)"
usage = version + """

Usage:

./webenum [-w wordlist] [-h header] [-d postdata] [-m match] url

URL, headers and POST data can contain:

  %%WORD%%, get strings from internal wordlist of ~900 common words.
  %%WORD[0-9]%% get strings from wordlist file paths specified in -w option.
  %%INT%%, generate integer ranges. Default: from 0 to 50.
  %%CHAR%%, generate character and string ranges. Default: from 'a' to 'z'.
  %%TABLE%%, generate 1,1,..,1 string, useful for SQL injection. Default: from 0 to 50.

  INT, CHAR and TABLE can be customized using [end] or [start]:[end], like %%INT4%% or %%CHARaa:zz%%.

Match (-m)

  To match correct responses, are supported little Python statements. HTTP Variables are response and status_code:
  "'Logged' in response and status_code == 200"
  "'Wrong password' in response"

POST datas (-d), headers (-h) and wordlists (-w):

  -d "param1=value" -d "param2=value" -d "param3=%%WORD%%"
  -h "User-Agent:Mozilla Firefox %%INT4:12%%.0" -h "Referer:%%WORD1%%"
  -w users.txt -w password.txt
  
"""


class struct:
  def __init__(self, **kwds):
    self.__dict__.update(kwds)

class request:

  url=''
  data={}
  headers={}

  opener=None

  def_wordlist=0
  fword=0
  fint=0
  fchar=0
  ftable=0
  
  tokens=[]
  
  def __init__(self, url, data = {}, headers = {}, cookiepath = ''):
    
    self.url=url
    self.headers=headers
    self.data=data
    
    self.opener=urllib2.build_opener()
    
    self.tokens = list(re.findall('%%WORD%%',self.url)) 
    for d in data:
      self.tokens += list(re.findall('%%WORD%%',data[d]))
    for h in headers:
      self.tokens += list(re.findall('%%WORD%%',headers[h]))
    
    if self.tokens:
      self.def_wordlist=1
    
    self.tokens += list(re.findall('%%WORD[0-9]%%',self.url)) 
    for d in data:
      self.tokens += list(re.findall('%%WORD[0-9]%%',data[d]))
    for h in headers:
      self.tokens += list(re.findall('%%WORD[0-9]%%',headers[h]))
    
    self.tokens.sort()
    self.fword=len(self.tokens)

    self.tokens += list(re.findall('%%INT\d*(?:\:\d+)?%%',self.url)) 
    for d in data:
      self.tokens += list(re.findall('%%INT\d*(?:\:\d+)?%%',data[d]))
    for h in headers:
      self.tokens += list(re.findall('%%INT\d*(?:\:\d+)?%%',headers[h]))
    
    self.fint=len(self.tokens)-self.fword

    self.tokens += list(re.findall('%%CHAR\w*(?:\:\w+)?%%',self.url)) 
    for d in data:
      self.tokens += list(re.findall('%%CHAR\w*(?:\:\w+)?%%',data[d]))
    for h in headers:
      self.tokens += list(re.findall('%%CHAR\w*(?:\:\w+)?%%',headers[h]))
    
    self.fchar=len(self.tokens)-self.fword-self.fint  
      
    self.tokens += list(re.findall('%%TABLE\d*(?:\:\d+)?%%',self.url)) 
    for d in data:
      self.tokens += list(re.findall('%%TABLE\d*(?:\:\d+)?%%',data[d]))
    for h in headers:
      self.tokens += list(re.findall('%%TABLE\d*(?:\:\d+)?%%',headers[h]))

    self.ftable=len(self.tokens)-self.fword-self.fint-self.fchar
    
  def replace(self,newtokens):
    
    if len(newtokens) != len(self.tokens):
      print '! Error, different number of tokens', len(newtokens), len(self.tokens)
      return None
    
    urlreplaced = self.url
    datareplaced = self.data.copy()
    hreplaced = self.headers.copy()
    
    for i in range(len(self.tokens)):
      
      if urlreplaced.find(self.tokens[i])>-1:
	urlreplaced = urlreplaced.replace(self.tokens[i], newtokens[i], 1)
	continue
      

      # Qua cambia data
      for d in datareplaced:
	if datareplaced[d].find(self.tokens[i])>-1:
	  datareplaced[d] = datareplaced[d].replace(self.tokens[i], newtokens[i], 1)
	  break

      # Qua cambia self.headers
      for h in hreplaced:
	if hreplaced[h].find(self.tokens[i])>-1:
	  hreplaced[h] = hreplaced[h].replace(self.tokens[i], newtokens[i], 1)
	  break
      
      
    toret = struct(url=urlreplaced, data=datareplaced, h=hreplaced)
    return toret
  
  
  def Get(self, url, data, head, r):
    
    rstring = ''
    
    url = urllib.quote(url, safe="%/:=&?~#+!$,;'@()*[]")
    #print url
    
    if not data:
      data = None
    else:
      data = urllib.urlencode(data)
    
    if r:
      head['User-Agent']=genUserAgent()
    if 'User-Agent' not in head:
      head['User-Agent']=version
    
    
    req = urllib2.Request(url, data, head)
    
    r = self.opener.open(req)
    rstring = r.read()
    
    return rstring
      
  def genUserAgent(self):
    agents = ['Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.14) Gecko/2009090216 Ubuntu/9.04 (jaunty) Firefox/3.0.14', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; GTB5; InfoPath.1)' ]
    
    #return agents[random.randint(0,len(agents)-1)]


class sqlenum:

  q=0
  
  foundlist= []
  notfoundlist=[]
  errorlist={}
  
  match=''
  
  opener=None
  req=None
 
  iterated=[]
  randomize=0
  

  def main(self):

    url=''
    data={}
    headers={}
    cookiepath=''

    split_wlists = []
    w=[]
    i=[]
    c=[]
    t=[]
    
    try:
	opts, args = getopt.getopt(sys.argv[1:-1], 'rw:m:v:d:h:c:', ['wordlist', 'match', 'verbose', 'data', 'headers', 'cookie'])
    except getopt.error, msg:
	print "Error:", msg
	print usage
	exit(2)
  
    
    
    if sys.argv[-1][:4] == 'http':
      url=sys.argv[-1]
    else:
      print '! Error, -u url required'
      print usage
      return -1      
  
  
    for o, a in opts:
      
	if o in ("-m", "-match"):
	  self.match=a
	if o in ("-w", "-wordlist"):
	  split_wlists.append(a)
	if o in ("-v", "-verbose"):
	  self.verbose = a
	if o in ("-d", "-data"):
	  d = a.split("=")
	  data[d[0]]=d[1]
	if o in ("-h", "-headers"):
	  h = a.split("=")
	  headers[h[0]]=h[1]
	if o in ("-c", "-cookie"):
	  cookiepath = a
	if o in ("-r", "-random"):
	  self.randomimze = 1
        
  
    if urllib2.getproxies():
      print '+ Using HTTP proxy ' + urllib2.getproxies()['http']

    self.req=request(url,data, headers, cookiepath)
    
    if self.req.fword:

      if self.req.fword-self.req.def_wordlist != len(split_wlists):
	print '! Error having ' + str(len(split_wlists)) + ' wordfile and ' + str(self.req.fword-self.req.def_wordlist) + ' %%WORD%%s parameters.' 
	return -1
        
      if self.req.def_wordlist==1 :
	w.append(w_default)
    
      try:

	for path in split_wlists:
	  f=open(path,'r')
	  
	  filelines=[]
	  for line in f.readlines(): 
	    filelines.append(line.strip())
	  
	  w.append(filelines)

      except Exception, e:
	print '! Error opening word lists: ' + str(e)
	return -1

    if self.req.fint:
     
      nums=[]
      for f in self.req.tokens:
	if f[2:5] == 'INT':
	  splitted=f[5:-2].split(':')
	  
	  if len(splitted)<2:
	    if not splitted[0]:
	      splitted=["0","50"]
	    else:
	      splitted=["0",splitted[0]]
	  
	  nums.append(splitted)
      
      ranges = [range(int(n), int(a)) for n,a in nums]
      
      for n in ranges:
	lst=[]
	for a in n:
	  lst.append(str(a))
	i.append(lst)
      
    
    if self.req.fchar:
      
      for f in self.req.tokens:
	if f[2:6] == 'CHAR':
	  splitted=f[6:-2].split(':')
	  
	  tosrc=[]
	  if len(splitted)<2:
	    if not splitted[0]:
	      splitted=["a","z"]
	    else:
	      splitted=["a"*len(splitted[0]),splitted[0]]
	  
	  tosrc.append(splitted)
	
	  # rang()ing the combination from aa to bb
	  ltrs=[]
	  for w1,w2 in tosrc:
	    for n in range(len(w1)):
	      founded = re.findall(w1[n] + '\w*' + w2[n],string.printable)
	      if founded:
		ltrs.append(list(founded)[0])
	      else:
		ltrs.append(w1)
	      
	  # joining combination to form words aa ab bb ba ..
	  ltrs2 = [''.join(l) for l in list(itertools.product(*ltrs))]
	  c.append(ltrs2)
	  
    if self.req.ftable:
      
      qnts=[]
      for f in self.req.tokens:
	if f[2:7] == 'TABLE':
	  splitted=f[7:-2].split(':')
	  
	  if len(splitted)<2:
	    if not splitted[0]:
	      splitted=["0","50"]
	    else:
	      splitted=["0",splitted[0]]
	  
	  qnts.append(splitted)
	  
	  for qnt in qnts:
	    table = []
	    for q in range(int(qnt[0]),int(qnt[1])+1):
	      if q:
		table.append(('1,'*(q))[:-1])
	    
	  t.append(table)



    if not self.match:
      print '! Error, one match string required.'
      return -1
    if self.match:
      self.eval_string = self.match
    
    try:
      eval(self.eval_string, {"response": "", "status_code" :0})
    except SyntaxError, e:
      print '! Wrong match string: ' + self.eval_string
      return -1
      
    self.iterated = list(itertools.product(*(w + i + c + t)))

    print '+ Generating', len(self.iterated), 'requests with:',
    if w:
      print str(len(w)), 'wordlists',
    if i:
      print str(len(i)), 'integers',
    if c:
      print str(len(c)), 'chars',
    if t:
      print str(len(t)), 'tables',
    print ''
      
      
    print '+ Matching response with ' + self.match 
   
    
    self.thread()
    
    print '\n+ Matched: ' + str(len(self.foundlist)) + ', not matched: ' + str(len(self.notfoundlist)) + ', request errors: ' + str(len(self.errorlist)) + '\n'
    
    if len(self.foundlist)>0:
      print '+ Printing matching requests:'
      for u in self.foundlist:
	print '+', u.url, 
	if self.req.data:
	  print u.data, 
	if self.req.headers:
	  print u.h,
	print ''
	

  def thread(self):
    
    while 1:
      
      try:
	items = list(self.iterated.pop(0))
      except IndexError:
	return
      
      reqdata = self.req.replace(items)
      
      if not reqdata:
	return -1
      
      status_code = 200
      try: 
	response = self.req.Get(reqdata.url,reqdata.data,reqdata.h,self.randomize)
      except urllib2.HTTPError, e:
	try:
	  response=e.read()
	except Exception, e:
	  self.errorlist[reqdata]="Error reading urllib2.HTTPError data"
	else:
	  if not response:
	    self.errorlist[reqdata]=str(e)
	  status_code=e.code
      except Exception, e:
	print str(e)
	self.errorlist[reqdata]=str(e)
	raise
      
      print '+', ', '.join(items),
      
      if response:
	
	ret=eval(self.eval_string, {"response": response, "status_code" :status_code})
	if ret:
	  print '... MATCH! (' + self.match + ') [' + str(status_code) + ']',
	  self.foundlist.append(reqdata)
	else:
	  self.notfoundlist.append(reqdata)
	  print '... doesn\'t match. [' + str(status_code) + ']',
	
      print ''
  
if __name__ == "__main__":
    
    app=sqlenum()
    try:
      app.main()
    except KeyboardInterrupt:
      print '\n! Received keyboard interrupt, exiting.'
