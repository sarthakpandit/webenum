#!/usr/bin/env python
# -*- coding: utf-8 -*-

# -------------------------------------------------------
#
# This code is released under the GNU / GPL v3
# You are free to use, edit and redistribuite it 
# under the terms of the GNU / GPL license.
# -------------------------------------------------------

import getopt, sys, urllib, urllib2, random, re, itertools, urlparse, string, threading, time, json, os

w_default = ["about","access","accesso", "accessi", "accounting", "account","accounts","accnt","adkit","admin", "adminlogin", "administracion","administrador","administrator","administrators","admins", "amministratore", "amministratori", "ads","affiliate","affiliates","afiliados", "affiliati", "agenda","agent","ajax","akamai","alerts","alpha","analyzer","announce","announcements","antivirus","apache","app","application","applications", "applicazioni", "apps","articolo", "articoli", "articles", "article", "auction","auth", "authenticate", "authentication", "autenticazione", "auto","av","b","back","backend","backup","banking","beta","billing","biz","blog","blogs","broadcast","bug","bugs","bugzilla","build","bulletins","buy","cache","calendar","careers","carrello", "carrelli","catalog","catalogo","cc", "carta", "carte", "cert","certificates", "certificato", "certificati","certify","certserv","certsrv","cgi","channel","channels","chat","chats","check","checkpoint","cisco","class","classes","classifieds","classroom","client", "cliente", "clienti", "clientes","clients","club","clubs","cluster","clusters","cmail","cms", "cms_users", "cms_passwords", "cms_accounts", "cms_admins", "cms_user", "cms_password", "cms_account", "cms_admin", "code","coldfusion","commerce","commerceserver","community","compras","concentrator","conference","conferencing","confidential","configuration", "configurazione", "config", "conf", "cfg", "connect","console","consult","consultant","consultants","consulting","consumer","contact", "contacts", "contatti", "content","contracts","core","corp","corpmail","corporate","correo","correoweb","courses","crm","css","customer","customers","cv","cvs","d","data", "dates","database01","database02","database1","database2","databases","datastore","datos","dati", "db","db0","db01","db02","db1","db2","dealers","def","default","delta","demo","demonstration","demos", "dimostrazione", "depot","design","designer","dev","devel","develop","developer","developers","development","device","devserver","devsql","dhcp","dial","dialup","digital","dir","direct","directory", "directories", "disc","discovery","discuss","discussion","discussions","disk", "disks", "distributer","distributers","dmail", "dnews","dns","do","docs","documentos","documents", "documentation", "documenti", "documento", "domain","domains","dominio","download","downloads","drupal","dyn","dynamic","e","e-com","e-commerce","echo","ecom","ecommerce","edu","ejemplo","esempio","email", "emails", "e-mail", "e-mails","employees","empresa","empresas","enable","eng","engine","engineer","engineering","enterprise","epsilon","estadisticas","esx","et","eta","europe","events","domain","exchange","extern","external","extranet","f","fax","feedback","feeds","field","file","files","fileserv","fileserver","filter","find","fix","fixes","flash","foobar","forum","forums","foto","fotos","foundry","freeware", "front","ftp","fw","galleria","galeria","galleries","gallery","games","gamma","gateway","gm","gmail","groups","guest","gw", "hash",  "hashes", "hello","help","helpdesk","helponline","hi","hidden","home","homes","host","hosts","hotel","howto","http","https","hub","humanresources","i","ids","iis","images","imail","img", "imgs","immagini", "image", "inc","include","incoming", "incomings", "info","inside","install","intern", "interno", "internal","international","internet","intl","intranet","invalid","investor","investors","invia","invio", "inviato", "inviati","io", "iscritto", "iscritti","jobs","job","kerberos","keynote","l","lab","laboratory","labs","lambda","lan","laptop","launch","ldap","legal","li","lib","library","link","lista", "liste", "lists", "list","live","load","local","localhost","log","log0","log1","log2","logfile","logfiles","logger","logging","loghost","login", "logins", "log-in", "logs", "logout", "loginout", "lotus","mac","master", "masters","mail","mailer","mailing","maillist","maillists","mailroom","mailserv","mailsite","mails","main","maint","mall","manage","management","manager","manufacturing","map","maps","marketing","marketplace","media", "medias", "member","members", "memberid", "members_id", "membri", "membro", "messages", "messaggi", "messaggio", "messenger","mirror","monitor","movies","mp3","mpeg","mpg","ms","msg", "msgs", "ms-exchange","ms-sql","msexchange","mssql","mssql0","mssql1","msysobject","multimedia","music","my","mysql","mysql0","mysql1","name","names", "nomi", "nome", "nat","net","netapp","netdata","netstats","network","new","news","novita", "notizia", "notizie", "newsfeed","newsfeeds","newsgroups","no","node","nomi", "nome", "noticias","null","office","offices","ok","old","online","open","operations","oracle","orders","out","outbound","outgoing","outlook","outside","p","page","pager","pages","pagine","pagina", "password", "pass", "pass_hash", "passw", "pword", "pwrd", "pwd", "pwds", "pw", "passes", "passwords", "partner","partners","patch","patches","pbx","pcmail", "personal", "personale","pgp","phi","phone","phones", "photos","pics","pictures", "pix","policy", "policies", "polls","pop","portal","portals","portfolio","post", "posts","posta","posta1","posta2","postoffice","press","printer","priv","privacy","private","privato","problems", "products", "prodotto", "prodotti","profiles", "profili", "profilo", "project","projects", "progetti", "progetto", "promo","proxy","prueba","prova","prove", "prova1", "prova2","pub","public","pubs","pubblico", "pubblici","pw","py","q","qmail","r","radius","read", "ricevuto", "ricevuti","ref","reference","reg","register","registro","registri","registry","regs","relay","rem","remote","reports","research","ricerca", "ricerche","reseller","reserved","resumenes","root","route","rs","rss","rw","s","s1","sadmin","safe","sales","scanner","schedules","sd","se","search", "searches", "sec","secret","secure","secured", "securid","security","sendmail","serv", "server","server1","servers","service","services", "servicio","servidor","setup", "settings", "setting", "shared","sharepoint","shareware","shipping","shop","shops","shoppers","shopping","sigma","sign","signin","signup","site","sms","smtp","snort","socal","soci", "socio","software","solutions","source","sourcecode","sources", "spam","sql","sqlserver","squid","ss","ssh","ssl","staff","stage","staging","start","stat","static","statistics","stats","stock","storage","store", "store1", "store2", "streaming","studio","submit","submission", "submissions", "subversion","sun","supplier","suppliers","support","sw","sysadmin", "sysadmins", "sysadm", "sysback","syslog","syslogs", "sysobjects", "system", "systems", "teams", "team","tech","techsupport","telephone","telephones","telephony","temp","temp1", "temp2", "terminal","testbed","testing","test","tests","testo","testserver","testsite","testsql","times","to", "todo","tool","tools","tracker","training","transfers", "trasferimenti","tumb","thumbnails", "thumbnail","tunnel","tv","updates","upload","uploads", "usr", "usrs", "usr1", "usr2", "user", "user1", "user2", "users","usuarios", "usuario", "utente", "utenti", "username", "user_name", "user_username", "uname", "usern", "user_password", "user_pass", "user_passw", "user_pwrd", "user_pwd", "user_id", "user_ids", "user_user", "user_users", "user_log","user_logs", "utilities","vend","vendors","venditori","video","videos","vm","vnc","voice","voicemail","voip","vpn","w", "wais","wallet","wap","w3c","web","webaccess","webadmin","webalizer","webboard","webcache","webcam","webcast","webdev","webdocs","webfarm","webhelp","weblib","weblogic","webmail","webmaster","webproxy","webs","webserv","webserver","webservices","website","websites","websphere","websrv","webstats","webstore","websvr","webtrends","welcome","whois","wiki","win","wlan","wordpress","work", "works","world","write","webserver", "ws","wusage","wv","ww","www","www-1", "www01", "www1","www2","www3","wwwdev","wwwmail","xmail","xml", "zone", "zones", "articoli"]

version = "WebEnum 0.1 (https://code.google.com/p/webenum/)"
usage = version + """

Usage:

./webenum [-h header] [-d postdata] url

Replace URL, POST data and headers parts using dynamic strings:

  ./webenum "http://www.target.com/query?param1=123,param2=[[wl:wordlist.txt]]"
  ./webenum "http://www.target.com/query" -d "param=[[int:100]]" -h "Referer:[[wl:referers-wordlist.txt]]"

  [[wl:wordlist.txt]]	load strings from a wordlist file.
  [[int:1:10]]		generate integer ranges. Default: from 0 to 50.
  [[char:aaa:zzz]]	generate string ranges. Default: from 'a' to 'z'.
  [[table:1:20]]	generate NULL,..,NULL strings to exploit SQL injection. Default: from 0 to 50 unos.

Match notable response 

  -m 'response.contains("correct login") and code != 404'
  -m 'not response.containsre(".*correct login.*") or code == 200'
  
"""

requestlistlock = threading.Lock()
outputlock = threading.Lock()
time2die = False
running = 0

#class struct:
  #def __init__(self, **kwds):
    #self.__dict__.update(kwds)

class outputHandler:
  
  hlist={}
  realpath=''
  
  def __init__(self, path='.'):
    
    self.path=path
    self.realpath=path
    
    ver=1
    while ver > 0:
      try:
	os.mkdir(self.path)
      except OSError:
	self.path=self.realpath + '-' + str(ver) +'/'
	ver+=1
      else:
	ver=-1

    if self.path[-1]!='/':
      self.path=self.path + '/'
    else:
      self.path=self.path

    
    print '+ Results saved in ' + self.path + 'results.html'
    
  def log(self,req):
    
    h = str(hash(req.response))
    if h[0]=='-':
      h= h[1:] + '-'
    
    if h not in self.hlist:
      f=open(self.path + h + '.html', 'w')
      f.write(req.response)
      f.close()
      self.hlist[h]=[[ req.url, req.data, req.head, req.params, req.status, req.error ]]
      return h
    else:
      self.hlist[h].append([ req.url, req.data, req.head, req.params, req.status, req.error ])
    

    self.res=open(self.path + 'result.js','w')
    self.res.write('var json = eval(\'(' + json.dumps(self.hlist) + ')\');\n')
    self.res.close()
    
    return ''
    

class request:
  def __init__(self, url, data, head, params, status=0,response='',error=''):
    self.url=url
    self.data=data
    self.head=head
    self.params=params
    
    self.status=status
    self.response=response
    self.error=error
  
def prettySize(size):
      suffixes = [("B",2**10), ("K",2**20), ("M",2**30), ("G",2**40), ("T",2**50)]
      for suf, lim in suffixes:
	      if size > lim:
		      continue
	      else:
		      return round(size/float(lim/2**10),2).__str__()+suf

class requestList:

  url=''

  opener=None

  fuzz=[]
  fuzzed=[]
  combfuzzed=[]
    

  def __init__(self, url, data = {}, headers = {}, cookiepath = '', combination=False):
    
    self.url=url
    self.data=data
    self.headers=headers
  
    
    self.fuzz += self.dissect(self.url)
    for d in data:
      self.fuzz += self.dissect(d)
      self.fuzz += self.dissect(data[d])
    for h in headers:
      self.fuzz += self.dissect(h)
      self.fuzz += self.dissect(headers[h])
  
    n=0
    for f, default in self.fuzz:
      
      # Loading wordlists
      if f[:3] == 'wl:':
	path=f[3:]
	filelines=[]
	
	try:
	  fl=open(path,'r')
	  
	  for line in fl.readlines(): 
	    filelines.append(line.strip())
	  
	  if default: filelines = [default] + filelines
	  self.fuzzed.append(filelines)

	except Exception, e:
	  print '! Error opening word lists: ' + str(e)
	  raise
	  return -1
	

      # Generating integers
      if f[:3] == 'int':
	splitted = []
	
	if len(f) == 3:
	  splitted=["0","50"]
	elif f[3] == ':':
	  splitted=f[4:].split(':')
	  if len(splitted)<2:
	    splitted=["0",splitted[0]]
	
	
	ranges = range(int(splitted[0]), int(splitted[1]))
	
	if default: ranges = [default] + ranges
	self.fuzzed.append([str(r) for r in ranges])
	
	
	# Generating character strings
	
      if f[:4] == 'char':
	splitted = []
	ltrs= []
	ltrs2 = []
	
	if len(f) == 4:
	  splitted=["a","z"]
	elif f[4] == ':':
	  splitted=f[5:].split(':')
	  if len(splitted)<2:
	    splitted=["a"*len(splitted[0]), splitted[0]]
	
	for n in range(len(splitted[0])):
	  founded = re.findall(splitted[0][n] + '\w*' + splitted[1][n],string.printable)
	  if founded:
	    ltrs.append(list(founded)[0])
	  else:
	    ltrs.append(w1)
	
	## joining combination to form words aa ab bb ba ..
	ltrs2 = [''.join(l) for l in list(itertools.product(*ltrs))]
	
	if default: ltrs2 = [default] + ltrs2
	self.fuzzed.append(ltrs2)
	
      if f[:5] == 'table':
	splitted = []
	table = []
	
	if len(f) == 5:
	  splitted=["1","50"]
	elif f[5] == ':':
	  
	  splitted=f[6:].split(':')
	  if len(splitted)<2:
	    splitted=["1", splitted[0]]
	
	for q in range(int(splitted[0]),int(splitted[1])+1):
	  table.append(('1,'*(q))[:-1])
	
	if default: table = [default] + table
	self.fuzzed.append(table)
	
    # Print summary
    n=0
    for f, default in self.fuzz:
      print '+ Loaded ' + str(len(self.fuzzed[n])) + ' requests for ' + f,
      if default:
	print '(including \'' + default + '\')',
      print ''
      n+=1
    
    if combination:
      self.combfuzzed = list(itertools.product(*(self.fuzzed)))
    else:
      for n in range(0,len(self.fuzzed)):
	for linea in self.fuzzed[n]:
	  
	  topush=[]
	  
	  for f2 in self.fuzzed:
	    if f2 != self.fuzzed[n]:
	      topush.append(f2[0])
	    else:
	      topush.append(linea)
	  
	  self.combfuzzed.append(topush)



  
  def dissect(self, string):
    
    tokens=[]
    
    tokens = list(re.findall('\[\[(wl:[^ |^\]]+)[ ]?([^\]]*)\]\]', string)) 
    tokens += list(re.findall('\[\[(int:\d*(?:\:\d+)?)[ ]?([^\]]*)\]\]', string))
    tokens += list(re.findall('\[\[(char:\w*(?:\:\w+)?)[ ]?([^\]]*)\]\]', string))
    tokens += list(re.findall('\[\[(table:\d*(?:\:\d+)?)[ ]?([^\]]*)\]\]', string))
    
    return tokens  
  
  def replacetoken(self,str1,f,new):
    
    if len(f)==1:
      f += ''
   
    newstr = re.sub('\[\[' + f[0] + '[ ]?(' + f[1] + ')?\]\]', new, str1)
    
    if newstr == str1:
      return ''
    
    return newstr
    
  
  def pop(self):
    
    newurl=self.url
    newdata=self.data.copy()
    newheaders=self.headers.copy()
    
    params = self.combfuzzed.pop(0)
    
    for n in range(0,len(params)):
      
      newurltemp = self.replacetoken(newurl,self.fuzz[n],params[n])
      
      if newurltemp: 
      
	newurl=newurltemp
	continue
      
      for d in newdata:
	newdatatemp = self.replacetoken(newdata[d],self.fuzz[n],params[n])
	if newdatatemp: 
	  newdata[d]=newdatatemp
	  continue
	
      for h in newheaders:
	newheaderstemp = self.replacetoken(newheaders[h],self.fuzz[n],params[n])
	
	if newheaderstemp:
	  newheaders[h]=newheaderstemp
	  continue

      

    return request(newurl, newdata, newheaders, params)
  


class reqthread ( threading.Thread ):

  def __init__ (self, reqlist, name, out):
    threading.Thread.__init__(self,group=None, name=str(name))
    self.opener=urllib2.build_opener()
    self.reqlist=reqlist
    self.out=out
    
  def run ( self ):
    
    global running 

    running+=1
    
    while 1:
      
      if time2die:
	print '! ' + self.name + ' forced exiting.'
	running-=1
	return
      
      try:
	requestlistlock.acquire()
	newreq=self.reqlist.pop()
	requestlistlock.release()
      except IndexError:
	requestlistlock.release()
	print '! ' + self.name + ' quitting, no more requests.'
	running-=1
	return

      req=self.httpget(newreq)
      
      outputlock.acquire()
      outfile = str(self.out.log(req))
      outputlock.release()
      if outfile:
	outfile= 'new output saved in ' + outfile + '.html'
      
      
      print '+ ' + self.name + '> [ ' + ' ][ '.join(req.params) + ' ]' + ' ... status: ' + str(req.status) + ' size: ' + prettySize(len(req.response)) + ' ' + outfile
    
  
    #if response:
      
      #ret=eval(self.eval_string, {"response": response, "status_code" :status_code})
      #if ret:
	#print '... MATCH! (' + self.match + ') [' + str(status_code) + ']',
	#self.foundlist.append(reqdata)
      #else:
	#self.notfoundlist.append(reqdata)
	#print '... doesn\'t match. [' + str(status_code) + ']',
      
    #print ''

  #class evaluated_resp:
    #def __init__(self,resp):
      #self.r=resp
    #def contains(self,what):
      #return what is in self.r
    #def containsre(self,what):
      #pass
      

  def httpget(self, req, r = None):
    
    rstring = ''
    
    url = urllib.quote(req.url, safe="%/:=&?~#+!$,;'@()*[]")
    
    if not req.data:
      data = None
    else:
      data = urllib.urlencode(req.data)
    
    h=req.head.copy()
    if r:
      h['User-Agent']=genUserAgent()
    if 'User-Agent' not in req.head:
      h['User-Agent']=version
    
    status_code = 200
    try: 
    
      reqsocket = urllib2.Request(url)
      r = self.opener.open(reqsocket)
      req.response = r.read()
    except urllib2.HTTPError, e:
      try:
	req.response=e.read()
      except Exception, e:
	req.error="Error reading urllib2.HTTPError data"
	print 'Error reading urllib2.HTTPError data'
	raise
      else:
	if not req.response:
	  req.error=str(e)
	req.status=e.code
    except Exception, e:
      print str(e)
      req.error=str(e)
      raise
    
    
    return req


      
  def genUserAgent(self):
    agents = ['Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6) Gecko/20070725 Firefox/2.0.0.6', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.14) Gecko/2009090216 Ubuntu/9.04 (jaunty) Firefox/3.0.14', 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; GTB5; InfoPath.1)' ]
    
    #return agents[random.randint(0,len(agents)-1)]


class webenum:

  foundlist= []
  notfoundlist=[]
  errorlist={}
  
  match=''
  
  req=None
 
  randomize=0
  

  def main(self):

    url=''
    data={}
    headers={}
    cookiepath=''
    
    resultpath=''
    threadsnum=3
    

    try:
	opts, args = getopt.getopt(sys.argv[1:], 'rw:m:v:d:h:c:t:', ['wordlist', 'match', 'verbose', 'data', 'headers', 'cookie', 'threads'])
    except getopt.error, msg:
	print "Error:", msg
	print usage
	exit(2)
  
    # argv[1] url
    
    if sys.argv[-1][:4] == 'http':
      url=sys.argv[-1]
      resultpath=urlparse.urlparse(url).netloc
    else:
      print '! Error, url required'
      print usage
      return -1      
    
    
    
    # argv[1]=='-', options
    for o, a in opts:
	if o in ("-m", "-match"):
	  self.match=a
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
	if o in ("-t", "-threads"):
	  if int(a)>0 or int(a)<50:
	    threadsnum=int(a)
	if o in ("-r", "-result"):
	  resultpath = a
        
    if urllib2.getproxies():
      print '+ Using HTTP proxy ' + urllib2.getproxies()['http']

    self.reqlist=requestList(url, data, headers, cookiepath)
    
    print '+ Covering ' + str(len(self.reqlist.combfuzzed)) + ' requests with ' + str(threadsnum) + ' thread/s'
    
    try:
      out = outputHandler(resultpath)
    except Exception, e:
      print '! Error creating ' + resultpath + ' log directory: ' + str(e)
      raise
      return -1
      
      
    
    for i in range(0,threadsnum):
      thread=reqthread(self.reqlist,i,out)
      thread.start()
    
    #try:
      #eval(self.eval_string, {"response": "", "status_code" :0})
    #except SyntaxError, e:
      #print '! Wrong match string: ' + self.eval_string
      #return -1
      
    #print '+ Oracle: ' + self.match 
   
    #print '\n+ Matched: ' + str(len(self.foundlist)) + ', not matched: ' + str(len(self.notfoundlist)) + ', request errors: ' + str(len(self.errorlist)) + '\n'
    
    #if len(self.foundlist)>0:
      #print '+ Printing matching requests:'
      #for u in self.foundlist:
	#print '+', u.url, 
	#if self.reqlist.data:
	  #print u.data, 
	#if self.reqlist.headers:
	  #print u.h,
	#print ''
	
if __name__ == "__main__":
    
    app=webenum()
    try:
      app.main()
      while running>0:
	time.sleep(1)
      print '! Exiting.'
      
    except (KeyboardInterrupt, SystemExit):
      print '! Received keyboard interrupt, quitting ' + str(running) + ' thread/s.'
      time2die=True
