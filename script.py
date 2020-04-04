import requests
import urllib.parse as urlparse
from urllib.parse import parse_qsl
from bs4 import BeautifulSoup

jsos_user = 'pwr284630'
jsos_pass = 'amcookieloff97'

s = requests.Session()

login_url = 'https://jsos.pwr.edu.pl/index.php/site/loginAsStudent'
r = s.get(login_url)
redirect_url = r.url
parsed = urlparse.urlparse(redirect_url)
tokens = dict(parse_qsl(parsed.query))

post_url = 'https://oauth.pwr.edu.pl/oauth/authenticate?0-1.IFormSubmitListener-authenticateForm&' + urlparse.urlencode(tokens)

post_static = {'authenticateButton': 'Zaloguj',
               'oauth_callback_url': 'https://jsos.pwr.edu.pl/index.php/site/loginAsStudent',
               'oauth_request_url': 'http://oauth.pwr.edu.pl/oauth/authenticate',
               'oauth_symbol': 'EIS',
               'id1_hf_0': ''}

post_credentials = {'username': jsos_user, 'password': jsos_pass}

form_data = post_static
form_data.update(tokens)
form_data.update(post_credentials)

r = s.post(post_url, form_data)

inbox_url = 'https://jsos.pwr.edu.pl/index.php/student/wiadomosci'
r = s.get(inbox_url)

soup = BeautifulSoup(r.text, 'html.parser')
for msg in soup.find_all('tr'):
    msg_url = msg.get('data-url')
    if msg_url:
        print(msg_url)