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


def check_credentials(jsos_user, jsos_pass, smail_user, smail_pass):
    creds_valid = {'jsos': False, 'smail': True}
    srv_ok = {'jsos': True, 'smail': True}
    try:
        check_srv = imaplib.IMAP4_SSL('student.pwr.edu.pl', 993)
    except:
        srv_ok['smail'] = False
        creds_valid['smail'] = False

    if srv_ok['smail']:
        try:
            check_srv.login(smail_user, smail_pass)
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

        post_credentials = {'username': jsos_user, 'password': jsos_pass}

        form_data = post_static
        form_data.update(tokens)
        form_data.update(post_credentials)

        r = s.post(post_url, form_data)
        if(r.url == 'https://jsos.pwr.edu.pl/index.php/student/indeksDane'):
            creds_valid['jsos'] = True

    except:
        srv_ok['jsos'] = False
    
    return {'srv_ok': srv_ok, 'creds_valid': creds_valid}


def msg_lookup(jsos_user, jsos_pass, smail_user, smail_pass, mode, check_jsos_anyways):

    if (check_jsos_anyways or mode == 'test'):
        unread = [True]
    else:
        check_srv = imaplib.IMAP4_SSL('student.pwr.edu.pl', 993)
        check_srv.login(smail_user, smail_pass)
        check_srv.select('INBOX')
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

        post_credentials = {'username': jsos_user, 'password': jsos_pass}

        form_data = post_static
        form_data.update(tokens)
        form_data.update(post_credentials)

        r = s.post(post_url, form_data)

        inbox_url = 'https://jsos.pwr.edu.pl/index.php/student/wiadomosci'
        r = s.get(inbox_url)

        soup1 = BeautifulSoup(r.text, 'html.parser')
        if mode == 'test':
            msgs = soup1.find_all('tr')
        else:
            msgs = soup1.find_all('tr', class_='unread')

        sent_count = 0
        if msgs:
            send_srv = smtplib.SMTP('student.pwr.edu.pl', 587)
            send_srv.starttls()
            send_srv.login(smail_user, smail_pass)

            for msg in msgs:
                msg_url = msg.get('data-url')
                
                if msg_url and not (mode == 'test' and sent_count > 2):
                    r = s.get('https://jsos.pwr.edu.pl' + msg_url)
                    soup2 = BeautifulSoup(r.text, 'html.parser')
                    msg_content = soup2.find('div', id='podgladWiadomosci')
                    
                    msg_author = msg_content.find('span', class_='text-bold').text.replace('Nadawca - ', '')
                    msg_author_split = msg_author.split()

                    if len(msg_author_split) > 2:
                        msg_author_email = 'jsos-noreply@student.pwr.edu.pl'
                    else:
                        msg_author_email = removeAccents(msg_author_split[1] + '.' + msg_author_split[0]).lower() + '@pwr.edu.pl'
                        
                    msg_title = '[JSOS] ' + msg_content.find('h4').text.replace('Temat - ', '')
                    msg_body = msg_content.find('div').text.replace('Treść wiadomości', '').replace('\n', '', 5)

                    email_msg = EmailMessage()
                    email_msg.set_content(msg_body)

                    email_msg['Subject'] = msg_title
                    email_msg['From'] = msg_author + ' <jsos-noreply@student.pwr.edu.pl>'
                    email_msg['Reply-to'] = msg_author_email
                    email_msg['To'] = smail_user

                    send_srv.send_message(email_msg)
                    sent_count += 1

            send_srv.quit()                

        if check_jsos_anyways or mode == 'test':
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


def set_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode):
    schedule.every().minute.do(msg_lookup, jsos_user, jsos_pass, smail_user, smail_pass, mode, False)
    schedule.every(3).hours.do(msg_lookup, jsos_user, jsos_pass, smail_user, smail_pass, mode, True)


def run_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode):
    print('Setting up scheduler...')
    set_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode)
    print('Scheduler up and running.')
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except SystemExit:
            print("\njml stopping gracefully, bye!")
            raise SystemExit
        except:
            print('An error has occured!')
            schedule.clear()
            set_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode)
            continue


def main(): 
    # Credentials' filename
    creds_file = '.creds'

    if os.path.isfile('./.env'):
        load_dotenv()

    jsos_user = os.getenv('JSOSU')
    jsos_pass = os.getenv('JSOSP')

    smail_user = os.getenv('SMAILU')
    smail_pass = os.getenv('SMAILP')

    mode = os.getenv('JMLMODE')
    mode = mode or 'normal'

    # Check if credentials retrieved from ENV variables
    if jsos_user and jsos_pass and smail_user and smail_pass:
        # Check credentials
            smail_user = add_smail_domain(smail_user)
            print('Checking credentials...')
            chck_cred = check_credentials(jsos_user, jsos_pass, smail_user, smail_pass)
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
                jsos_user = decrypt(cred_key, creds['jsosu']).decode()
                jsos_pass = decrypt(cred_key, creds['jsosp']).decode()
                smail_user = decrypt(cred_key, creds['smailu']).decode()
                smail_pass = decrypt(cred_key, creds['smailp']).decode()
                print('Credentials loaded!')
            except ValueError:
                print('Invalid key! Cannot decrypt credentials, bye!')
                raise SystemExit

        else:
            # Ask for credentials
            jsos_user = input('JSOS login: ')
            jsos_pass = getpass.getpass('JSOS password: ')

            smail_user = add_smail_domain(input('SMAIL login: '))
            smail_pass = getpass.getpass('SMAIL password: ')

            # Check credentials
            print('Checking credentials...')
            chck_cred = check_credentials(jsos_user, jsos_pass, smail_user, smail_pass)
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

            ask_store = input('Do you want to save your credentials? (y/n) [n]: ')
            if ask_store == 'y':
                cred_key = getpass.getpass('Enter an encryption key: ')
                cred_key = cred_key.encode()
                # Encrypt credentials
                creds = {
                    'jsosu': encrypt(cred_key, jsos_user.encode()),
                    'jsosp': encrypt(cred_key, jsos_pass.encode()),
                    'smailu': encrypt(cred_key, smail_user.encode()),
                    'smailp': encrypt(cred_key, smail_pass.encode())
                }
                cred_key = None

                # Serialize encrypted credentials to a file
                cred_out = open(creds_file, 'wb')
                pickle.dump(creds, cred_out)
                cred_out.close()
                print('Credentials encrypted and saved!')

        ask_mode = input('Run in a test mode? (y/n) [n]: ')
        if ask_mode == 'y':
            mode = 'test'
        else:
            mode = 'normal'
    print('Running in ' + mode + ' mode.')
    run_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode)
     
if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()