#!/usr/bin/env python3
# coding=utf-8

import signal
import requests
import os
from dotenv import load_dotenv
import getpass
import schedule
import time
from datetime import datetime

import urllib.parse as urlparse
from urllib.parse import parse_qsl
from bs4 import BeautifulSoup

import imaplib
import smtplib
from email.message import EmailMessage

import base64
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random

import pickle

# define Python user-defined exceptions
class Alert(Exception):
   """Base class for alert exceptions"""
   pass

class ErrorAlert(Alert):
   """Raised when error alert is sent"""
   pass

class WorkingAlert(Alert):
   """Raised when working alert is sent"""
   pass

class NotSentAlert(Alert):
   """Raised when alert could not be sent"""
   pass

class ErrorCountException(Exception):
    """Raised when error count is not equal 0 after successful msg lookup"""
    pass

def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode("latin-1") if encode else data


def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode("latin-1"))
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


def signal_handler(signal, frame):
    raise SystemExit


def removeAccents(input_text):

    strange='ŮôῡΒძěἊἦëĐᾇόἶἧзвŅῑἼźἓŉἐÿἈΌἢὶЁϋυŕŽŎŃğûλВὦėἜŤŨîᾪĝžἙâᾣÚκὔჯᾏᾢĠфĞὝŲŊŁČῐЙῤŌὭŏყἀхῦЧĎὍОуνἱῺèᾒῘᾘὨШūლἚύсÁóĒἍŷöὄЗὤἥბĔõὅῥŋБщἝξĢюᾫაπჟῸდΓÕűřἅгἰშΨńģὌΥÒᾬÏἴქὀῖὣᾙῶŠὟὁἵÖἕΕῨčᾈķЭτἻůᾕἫжΩᾶŇᾁἣჩαἄἹΖеУŹἃἠᾞåᾄГΠКíōĪὮϊὂᾱიżŦИὙἮὖÛĮἳφᾖἋΎΰῩŚἷРῈĲἁéὃσňİΙῠΚĸὛΪᾝᾯψÄᾭêὠÀღЫĩĈμΆᾌἨÑἑïოĵÃŒŸζჭᾼőΣŻçųøΤΑËņĭῙŘАдὗპŰἤცᾓήἯΐÎეὊὼΘЖᾜὢĚἩħĂыῳὧďТΗἺĬὰὡὬὫÇЩᾧñῢĻᾅÆßшδòÂчῌᾃΉᾑΦÍīМƒÜἒĴἿťᾴĶÊΊȘῃΟúχΔὋŴćŔῴῆЦЮΝΛῪŢὯнῬũãáἽĕᾗნᾳἆᾥйᾡὒსᾎĆрĀüСὕÅýფᾺῲšŵкἎἇὑЛვёἂΏθĘэᾋΧĉᾐĤὐὴιăąäὺÈФĺῇἘſგŜæῼῄĊἏØÉПяწДĿᾮἭĜХῂᾦωთĦлðὩზკίᾂᾆἪпἸиᾠώᾀŪāоÙἉἾρаđἌΞļÔβĖÝᾔĨНŀęᾤÓцЕĽŞὈÞუтΈέıàᾍἛśìŶŬȚĳῧῊᾟάεŖᾨᾉςΡმᾊᾸįᾚὥηᾛġÐὓłγľмþᾹἲἔбċῗჰხοἬŗŐἡὲῷῚΫŭᾩὸùᾷĹēრЯĄὉὪῒᾲΜᾰÌœĥტ'

    ascii_replacements='UoyBdeAieDaoiiZVNiIzeneyAOiiEyyrZONgulVoeETUiOgzEaoUkyjAoGFGYUNLCiIrOOoqaKyCDOOUniOeiIIOSulEySAoEAyooZoibEoornBSEkGYOapzOdGOuraGisPngOYOOIikoioIoSYoiOeEYcAkEtIuiIZOaNaicaaIZEUZaiIaaGPKioIOioaizTIYIyUIifiAYyYSiREIaeosnIIyKkYIIOpAOeoAgYiCmAAINeiojAOYzcAoSZcuoTAEniIRADypUitiiIiIeOoTZIoEIhAYoodTIIIaoOOCSonyKaAsSdoACIaIiFIiMfUeJItaKEISiOuxDOWcRoiTYNLYTONRuaaIeinaaoIoysACRAuSyAypAoswKAayLvEaOtEEAXciHyiiaaayEFliEsgSaOiCAOEPYtDKOIGKiootHLdOzkiaaIPIIooaUaOUAIrAdAKlObEYiINleoOTEKSOTuTEeiaAEsiYUTiyIIaeROAsRmAAiIoiIgDylglMtAieBcihkoIrOieoIYuOouaKerYAOOiaMaIoht'

    translator=str.maketrans(strange,ascii_replacements)

    return input_text.translate(translator)


def add_smail_domain(smail_user):
    domain = '@student.pwr.edu.pl'
    if smail_user.find(domain) < 0:
        smail_user = smail_user + domain
    return smail_user


def check_credentials(settings):
    creds_valid = {'jsos': False, 'smail': True}
    srv_ok = {'jsos': True, 'smail': True}
    try:
        check_srv = imaplib.IMAP4_SSL('imap.gmail.com', 993)
    except:
        srv_ok['smail'] = False
        creds_valid['smail'] = False

    if srv_ok['smail']:
        try:
            check_srv.login(settings['smail_user'], settings['smail_pass'])
        except:
            creds_valid['smail'] = False
        check_srv.logout()

    try:
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

        post_credentials = {'username': settings['jsos_user'], 'password': settings['jsos_pass']}

        form_data = post_static
        form_data.update(tokens)
        form_data.update(post_credentials)

        r = s.post(post_url, form_data)
        if(r.url == 'https://jsos.pwr.edu.pl/index.php/student/indeksDane'):
            creds_valid['jsos'] = True

    except:
        srv_ok['jsos'] = False
    
    return {'srv_ok': srv_ok, 'creds_valid': creds_valid}


def msg_lookup(settings, errors, check_jsos_anyways):
    send_alert(settings['webhook'], errors)

    if (check_jsos_anyways or settings['mode'] == 'test'):
        unread = [True]
    else:
        check_srv = imaplib.IMAP4_SSL('imap.gmail.com', 993)
        check_srv.login(settings['smail_user'], settings['smail_pass'])
        check_srv.select('inbox')
        _status, unread = check_srv.search(None, '(SUBJECT "[Edukacja.CL] powiadomienie o otrzymaniu nowego komunikatu" UNSEEN)')
    
    if unread[0]:
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

        post_credentials = {'username': settings['jsos_user'], 'password': settings['jsos_pass']}

        form_data = post_static
        form_data.update(tokens)
        form_data.update(post_credentials)

        r = s.post(post_url, form_data)

        inbox_url = 'https://jsos.pwr.edu.pl/index.php/student/wiadomosci'
        r = s.get(inbox_url)

        soup1 = BeautifulSoup(r.text, 'html.parser')
        if settings['mode'] == 'test':
            msgs = soup1.find_all('tr')
        else:
            msgs = soup1.find_all('tr', class_='unread')

        sent_count = 0
        if msgs:
            send_srv = smtplib.SMTP('smtp.gmail.com', 587)
            send_srv.starttls()
            send_srv.login(settings['smail_user'], settings['smail_pass'])

            for msg in msgs:
                msg_url = msg.get('data-url')
                
                if msg_url and not (settings['mode'] == 'test' and sent_count > 2):
                    r = s.get('https://jsos.pwr.edu.pl' + msg_url)
                    soup2 = BeautifulSoup(r.text, 'html.parser')
                    msg_content = soup2.find('div', id='podgladWiadomosci')
                    
                    msg_author = msg_content.find('span', class_='text-bold').text.replace('Nadawca - ', '')
                    msg_author_split = msg_author.split()

                    if len(msg_author_split) > 2:
                        msg_author_email = 'jsos-noreply@student.pwr.edu.pl'
                    else:
                        msg_author_email = removeAccents(msg_author_split[1] + '.' + msg_author_split[0]).lower() + '@pwr.edu.pl'
                        
                    msg_title = msg_content.find('h4').text.replace('Temat - ', '')
                    msg_body = msg_content.find('div').text.replace('Treść wiadomości', '').replace('\n', '', 5)

                    if settings['mode'] == 'webhook' or (settings['mode'] == 'test' and settings['webhook']):
                        msg_json = {
                            "type": "message",
                            "author": msg_author,
                            "author_email": msg_author_email,
                            "title": msg_title,
                            "body": msg_body,
                            "msg": msg_author + "\n*" + msg_title + "*\n\n" + msg_body + "\n___"
                        }
                        r = requests.post(settings['webhook'], json=msg_json)

                    if settings['mode'] == 'normal' or settings['mode'] == 'test':
                        email_msg = EmailMessage()
                        email_msg.set_content(msg_body)

                        email_msg['Subject'] = '[JSOS] ' + msg_title
                        email_msg['From'] = msg_author + ' <jsos-noreply@student.pwr.edu.pl>'
                        email_msg['Reply-to'] = msg_author_email
                        email_msg['To'] = settings['smail_user']

                        send_srv.send_message(email_msg)
                    sent_count += 1

            send_srv.quit()                

        if check_jsos_anyways or settings['mode'] == 'test':
            log_msg = 'Emails: not-checked, JSOS messages: ' + str(sent_count)
        else:
            for e_id in unread[0].split():
                check_srv.store(e_id, '+FLAGS', r'\Seen')
            log_msg = 'Emails: ' + str(len(unread[0].split())) + ', JSOS messages: ' + str(sent_count)
            check_srv.logout()
    else:
        log_msg = 'Emails: 0, JSOS messages: not-checked'   
    now = datetime.now()
    log_msg = '[' + now.strftime("%d/%m/%Y %H:%M:%S") + '] ' + log_msg
    print(log_msg)
    clear_error_count(errors)

def webhook_alert(webhook, error_count):
    if error_count < 0:
        title = "[jml] Working again."
        body = "It looks like your jml is fine and working again. Enjoy!"
    else:
        title = "[jml] Error alert!"
        body = "Your jml was not able to check or deliver new JSOS messages for last " + str(error_count) + " attempts. Perhaps one of pwr's services (JSOS or SMAIL) is not working properly or your jml's host lost an internet connection for a while. Go to https://edukacja.pwr.wroc.pl/ to check messages manually."
    json = {
        "type": "alert",
        "author": "jml",
        "author_email": "None",
        "title": title,
        "body": body,
        "errors": error_count,
        "msg": "*" + title + "*\n" + body + "\n___"
    }
    return json

def send_alert(webhook, errors):
    if errors['count'] >= errors['alert_at'] and webhook:
        print('Reached ' + str(errors['alert_at']) + ' errors in a row. Sending an alert...')
        try:
            requests.post(webhook, json=webhook_alert(webhook, errors['count']))
        except:
            print('Could not send the alert, check your internet connection.')
            raise NotSentAlert
        print('Alert sent.')
        raise ErrorAlert

    if errors['count'] < 0 and webhook:
        print('Working fine again. Sending alert...')
        try:
            requests.post(webhook, json=webhook_alert(webhook, errors['count']))
        except:
            print('Could not send the alert, check your internet connection.')
            raise NotSentAlert
        print('Alert sent.')
        raise WorkingAlert

def clear_error_count(errors):
    if errors['count'] > 0 or errors['alert_sent']:
        raise ErrorCountException

def set_scheduler(settings, errors):
    schedule.clear()
    schedule.every().minute.do(msg_lookup, settings, errors, False)
    schedule.every(2).hours.do(msg_lookup, settings, errors, True)


def run_scheduler(settings):
    errors = {
        'count': 0,
        'alert_at': 10,
        'alert_sent': False
    }
    print('Setting up scheduler...')
    set_scheduler(settings, errors)
    print('Scheduler up and running.')
    
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)

        except SystemExit:
            print("\njml stopping gracefully, bye!")
            raise SystemExit
        
        except ErrorAlert:
            errors['count'] = 0
            errors['alert_sent'] = True
            set_scheduler(settings, errors)
            continue

        except WorkingAlert:
            errors['count'] = 0
            errors['alert_sent'] = False
            set_scheduler(settings, errors)

        except NotSentAlert:
            set_scheduler(settings, errors)
            continue

        except ErrorCountException:
            if(errors['alert_sent']):
                errors['count'] = -1
            else:
                errors['count'] = 0
            set_scheduler(settings, errors)
            continue

        except Exception as e:
            print('An error has occured: ' + type(e).__name__)
            errors['count'] = errors['count'] + 1
            set_scheduler(settings, errors)
            continue

def main(): 
    # Credentials' filename
    creds_file = '.creds'
    settings = {}
    modes = {
        'n': 'normal',
        't': 'test',
        'w': 'webhook'
    }

    if os.path.isfile('./.env'):
        load_dotenv()

    settings['jsos_user'] = os.getenv('JSOSU')
    settings['jsos_pass'] = os.getenv('JSOSP')

    settings['smail_user'] = os.getenv('SMAILU')
    settings['smail_pass'] = os.getenv('SMAILP')

    settings['mode'] = os.getenv('JMLMODE')
    if not settings['mode'] == modes['t'] and not settings['mode'] == modes['w']:
        settings['mode'] = modes['n']

    settings['webhook'] = os.getenv('JMLWEBHOOK')
    if not settings['webhook']:
        settings['webhook'] = False

    # Check if credentials retrieved from ENV variables
    if settings['jsos_user'] and settings['jsos_pass'] and settings['smail_user'] and settings['smail_pass']:
        # Check credentials
            settings['smail_user'] = add_smail_domain(settings['smail_user'])
            print('Checking credentials...')
            chck_cred = check_credentials(settings)
            if chck_cred['srv_ok']['jsos'] and chck_cred['srv_ok']['smail']:
                if chck_cred['creds_valid']['jsos'] and chck_cred['creds_valid']['smail']:
                    print('Credentials OK.')
                else:
                    if not chck_cred['creds_valid']['jsos']:
                        print('Invalid JSOS credentials!')
                    if not chck_cred['creds_valid']['smail']:
                        print('Invalid SMAIL credentials!')
                    print('Bye.')
                    raise SystemExit
            else:
                if not chck_cred['srv_ok']['jsos']:
                    print('JSOS not accessible!')
                if not chck_cred['srv_ok']['smail']:
                    print('Email server not accessible!')
                print('Bye.')
                raise SystemExit
    else:
        # Check if credentials file exists
        if os.path.isfile(creds_file):
            # Load credentials from the file
            print('Found saved credentials.')
            cred_key = getpass.getpass('Enter a key to decrypt: ')
            cred_key = cred_key.encode()
            cred_in = open(creds_file, 'rb')
            creds = pickle.load(cred_in)
            cred_in.close()

            # Decrypt credentials
            try:
                settings['jsos_user'] = decrypt(cred_key, creds['jsosu']).decode()
                settings['jsos_pass'] = decrypt(cred_key, creds['jsosp']).decode()
                settings['smail_user'] = decrypt(cred_key, creds['smailu']).decode()
                settings['smail_pass'] = decrypt(cred_key, creds['smailp']).decode()
                if creds['webhook']:
                    settings['webhook'] = decrypt(cred_key, creds['webhook']).decode()
                print('Credentials loaded!')
            except ValueError:
                print('Invalid key! Cannot decrypt credentials, bye!')
                raise SystemExit
            cred_key = None

        else:
            # Ask for credentials
            settings['jsos_user'] = input('JSOS login: ')
            settings['jsos_pass'] = getpass.getpass('JSOS password: ')

            settings['smail_user'] = add_smail_domain(input('SMAIL login: '))
            settings['smail_pass'] = getpass.getpass('SMAIL password: ')

            # Check credentials
            print('Checking credentials...')
            chck_cred = check_credentials(settings)
            if chck_cred['srv_ok']['jsos'] and chck_cred['srv_ok']['smail']:
                if chck_cred['creds_valid']['jsos'] and chck_cred['creds_valid']['smail']:
                    print('Credentials OK.')
                else:
                    if not chck_cred['creds_valid']['jsos']:
                        print('Invalid JSOS credentials!')
                    if not chck_cred['creds_valid']['smail']:
                        print('Invalid SMAIL credentials!')
                    print('Bye.')
                    raise SystemExit
            else:
                if not chck_cred['srv_ok']['jsos']:
                    print('JSOS not accessible!')
                if not chck_cred['srv_ok']['smail']:
                    print('Email server not accessible!')
                print('Bye.')
                raise SystemExit

            if not settings['webhook']:
                ask_webhook = input('Do you want to add a webhook? (y/n) [n]: ')
                if ask_webhook == 'y':
                    settings['webhook'] = input('Webhook URL: ')
            else:
                print('Webhook loaded from ENV.')
                print('Webhook URL: ' + settings['webhook'])

            ask_store = input('Do you want to encrypt and save your credentials? (y/n) [y]: ')
            if ask_store != 'n':
                cred_key = getpass.getpass('Enter an encryption key: ')
                cred_key = cred_key.encode()
                # Encrypt credentials
                creds = {
                    'jsosu': encrypt(cred_key, settings['jsos_user'].encode()),
                    'jsosp': encrypt(cred_key, settings['jsos_pass'].encode()),
                    'smailu': encrypt(cred_key, settings['smail_user'].encode()),
                    'smailp': encrypt(cred_key, settings['smail_pass'].encode()),
                    'webhook': False
                }
                if settings['webhook']:
                    creds['webhook'] = encrypt(cred_key, settings['webhook'].encode())
                
                # Unset encryption key variable after encrypting credentials
                cred_key = None

                # Serialize encrypted credentials to a file
                cred_out = open(creds_file, 'wb')
                pickle.dump(creds, cred_out)
                cred_out.close()
                print('Credentials encrypted and saved!')
        
        webhook_option = ''
        if settings['webhook']:
            webhook_option = '/[w]ebhook'

        ask_mode = input('Select mode [n]ormal/[t]est' + webhook_option + ' [' + settings['mode'][0] + ']: ')
        settings['mode'] = modes.get(ask_mode, settings['mode'])

    if settings['mode'] == modes['w'] and not settings['webhook']:
        print('Webhook not provided. Cannot run in webhook mode, bye!')
        raise SystemExit
        
    print('Running in ' + settings['mode'] + ' mode.')
    run_scheduler(settings)
     
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()