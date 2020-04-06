# coding=utf-8
import sys, signal
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

def signal_handler(signal, frame):
    raise SystemExit

def removeAccents(input_text):

    strange='ŮôῡΒძěἊἦëĐᾇόἶἧзвŅῑἼźἓŉἐÿἈΌἢὶЁϋυŕŽŎŃğûλВὦėἜŤŨîᾪĝžἙâᾣÚκὔჯᾏᾢĠфĞὝŲŊŁČῐЙῤŌὭŏყἀхῦЧĎὍОуνἱῺèᾒῘᾘὨШūლἚύсÁóĒἍŷöὄЗὤἥბĔõὅῥŋБщἝξĢюᾫაπჟῸდΓÕűřἅгἰშΨńģὌΥÒᾬÏἴქὀῖὣᾙῶŠὟὁἵÖἕΕῨčᾈķЭτἻůᾕἫжΩᾶŇᾁἣჩαἄἹΖеУŹἃἠᾞåᾄГΠКíōĪὮϊὂᾱიżŦИὙἮὖÛĮἳφᾖἋΎΰῩŚἷРῈĲἁéὃσňİΙῠΚĸὛΪᾝᾯψÄᾭêὠÀღЫĩĈμΆᾌἨÑἑïოĵÃŒŸζჭᾼőΣŻçųøΤΑËņĭῙŘАдὗპŰἤცᾓήἯΐÎეὊὼΘЖᾜὢĚἩħĂыῳὧďТΗἺĬὰὡὬὫÇЩᾧñῢĻᾅÆßшδòÂчῌᾃΉᾑΦÍīМƒÜἒĴἿťᾴĶÊΊȘῃΟúχΔὋŴćŔῴῆЦЮΝΛῪŢὯнῬũãáἽĕᾗნᾳἆᾥйᾡὒსᾎĆрĀüСὕÅýფᾺῲšŵкἎἇὑЛვёἂΏθĘэᾋΧĉᾐĤὐὴιăąäὺÈФĺῇἘſგŜæῼῄĊἏØÉПяწДĿᾮἭĜХῂᾦωთĦлðὩზკίᾂᾆἪпἸиᾠώᾀŪāоÙἉἾρаđἌΞļÔβĖÝᾔĨНŀęᾤÓцЕĽŞὈÞუтΈέıàᾍἛśìŶŬȚĳῧῊᾟάεŖᾨᾉςΡმᾊᾸįᾚὥηᾛġÐὓłγľмþᾹἲἔбċῗჰხοἬŗŐἡὲῷῚΫŭᾩὸùᾷĹēრЯĄὉὪῒᾲΜᾰÌœĥტ'

    ascii_replacements='UoyBdeAieDaoiiZVNiIzeneyAOiiEyyrZONgulVoeETUiOgzEaoUkyjAoGFGYUNLCiIrOOoqaKyCDOOUniOeiIIOSulEySAoEAyooZoibEoornBSEkGYOapzOdGOuraGisPngOYOOIikoioIoSYoiOeEYcAkEtIuiIZOaNaicaaIZEUZaiIaaGPKioIOioaizTIYIyUIifiAYyYSiREIaeosnIIyKkYIIOpAOeoAgYiCmAAINeiojAOYzcAoSZcuoTAEniIRADypUitiiIiIeOoTZIoEIhAYoodTIIIaoOOCSonyKaAsSdoACIaIiFIiMfUeJItaKEISiOuxDOWcRoiTYNLYTONRuaaIeinaaoIoysACRAuSyAypAoswKAayLvEaOtEEAXciHyiiaaayEFliEsgSaOiCAOEPYtDKOIGKiootHLdOzkiaaIPIIooaUaOUAIrAdAKlObEYiINleoOTEKSOTuTEeiaAEsiYUTiyIIaeROAsRmAAiIoiIgDylglMtAieBcihkoIrOieoIYuOouaKerYAOOiaMaIoht'

    translator=str.maketrans(strange,ascii_replacements)

    return input_text.translate(translator)

def msg_lookup(jsos_user, jsos_pass, smail_user, smail_pass, mode, check_jsos_anyways):

    if (check_jsos_anyways or mode == 'test'):
        unread = [True]
    else:
        check_srv = imaplib.IMAP4_SSL('student.pwr.edu.pl', 993)
        check_srv.login(smail_user, smail_pass)
        check_srv.select('INBOX')
        status, unread = check_srv.search(None, '(SUBJECT "[Edukacja.CL] powiadomienie o otrzymaniu nowego komunikatu" UNSEEN)')
    
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
                check_srv.store(e_id, '+FLAGS', '\Seen')
            log_msg = 'Emails: ' + str(len(unread[0].split())) + ', JSOS messages: ' + str(sent_count)
            check_srv.logout()
    else:
        log_msg = 'Emails: 0, JSOS messages: not-checked'   
    now = datetime.now()
    log_msg = '[' + now.strftime("%d/%m/%Y %H:%M:%S") + '] ' + log_msg
    print(log_msg)

def set_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode):
    schedule.every(30).seconds.do(msg_lookup, jsos_user, jsos_pass, smail_user, smail_pass, mode, False)
    schedule.every(2).hours.do(msg_lookup, jsos_user, jsos_pass, smail_user, smail_pass, mode, True)

def run_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode):
    set_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode)
    while True:
        try:
            schedule.run_pending()
            time.sleep(1)
        except SystemExit:
            print("\njml stopping gracefully, bye!")
            sys.exit(0)
        except:
            print('Error!')
            schedule.clear()
            set_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode)
            continue

def main(): 
    if os.path.isfile('./.env'):
        load_dotenv()

    jsos_user = os.getenv('JSOSU')
    jsos_pass = os.getenv('JSOSP')

    smail_user = os.getenv('SMAILU')
    smail_pass = os.getenv('SMAILP')

    mode = os.getenv('JMLMODE')
    mode = mode or 'normal'

    if not (jsos_user and jsos_pass and smail_user and smail_pass):
        jsos_user = input("JSOS login: ")
        jsos_pass = getpass.getpass("JSOS password: ")

        smail_user = input("SMAIL login: ")
        smail_pass = getpass.getpass("SMAIL password: ")

        ask_mode = input("Run in a test mode? (y/n) [n]: ")
        if ask_mode == 'y':
            mode = 'test'
        else:
            mode = 'normal'
   
    run_scheduler(jsos_user, jsos_pass, smail_user, smail_pass, mode)

        

if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    main()