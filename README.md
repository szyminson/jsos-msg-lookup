# JSOS message lookup
Read JSOS messages straight from your email client!
<!-- vscode-markdown-toc -->
* 1. [Description](#Description)
* 2. [Usage](#Usage)
		* 2.1. [Note](#Note)
	* 2.1. [The most secure way](#Themostsecureway)
		* 2.1.1. [Saving ecnrypted credentials](#Savingecnryptedcredentials)
		* 2.1.2. [Deleting saved credentials](#Deletingsavedcredentials)
	* 2.2. [Less secure but easier to automate way](#Lesssecurebuteasiertoautomateway)
	* 2.3. [Termux usage](#Termuxusage)
		* 2.3.1. [Install Termux](#InstallTermux)
		* 2.3.2. [Install jml](#Installjml)
* 3. [Credentials importing order](#Credentialsimportingorder)
	* 3.1. [Example](#Example)
* 4. [Modes](#Modes)
	* 4.1. [Test mode](#Testmode)
	* 4.2. [Normal mode](#Normalmode)
	* 4.3. [Webhook mode](#Webhookmode)
* 5. [Webhooks and alerts](#Webhooksandalerts)
	* 5.1. [Error alert](#Erroralert)
	* 5.2. [Working alert](#Workingalert)
	* 5.3. [JSON parameters](#JSONparameters)
		* 5.3.1. [Alert](#Alert)
		* 5.3.2. [Message](#Message)

<!-- vscode-markdown-toc-config
	numbering=true
	autoSave=true
	/vscode-markdown-toc-config -->
<!-- /vscode-markdown-toc -->

##  1. <a name='Description'></a>Description
JSOS message lookup (*jml*) checks your SMAIL inbox every minute using SSL IMAP and python scheduler. If there is an **unread** email from Edukacja.CL about a new message waiting for you on JSOS, jml logs into your JSOS account, just like you would do it in your browser (using HTTP requests) and retrieves new message's title, body and author. Then a new email message containing all retrieved data is sent to your SMAIL inbox using SMTP TLS.  

##  2. <a name='Usage'></a>Usage
Tested on Python `3.6.9` and `3.7.3`. 

####  2.1. <a name='Note'></a>Note
Remember to install required packages before running jml: 
```
$ pip3 install -r requirements.txt
```

###  2.1. <a name='Themostsecureway'></a>The most secure way
Just run jml:
```
$ python3 jml.py
```
It will ask you for your JSOS and SMAIL credentials.

####  2.1.1. <a name='Savingecnryptedcredentials'></a>Saving ecnrypted credentials
After providing jml with your credentials you will be asked if you want to save them. If you decide to do it, you'll be prompted to provide an encryption key. AES256 CBC is used for encryption. Next time you run the jml it will only ask you for the encryption key to decrypt stored credentials. 

####  2.1.2. <a name='Deletingsavedcredentials'></a>Deleting saved credentials
Delete `.creds` file from jml's directory.

###  2.2. <a name='Lesssecurebuteasiertoautomateway'></a>Less secure but easier to automate way
You can optionally provide jml with your credentials using environment variables. Place `.env` file constructed as `.env.example` shows in jml's directory or export your env variables before running jml.

###  2.3. <a name='Termuxusage'></a>Termux usage
####  2.3.1. <a name='InstallTermux'></a>Install Termux
Install `Termux` along with `Termux:API` and `Termux:Boot`. Please keep in mind that in order to get `Termux` and its plugins to work together flawlessly you have to install them from the same app store (Google Play or F-Droid). 
* Termux [Google Play](https://play.google.com/store/apps/details?id=com.termux) (Free) | [F-Droid](https://f-droid.org/packages/com.termux/) (Free),
* Termux:API [Google Play](https://play.google.com/store/apps/details?id=com.termux.api) (Free) | [F-Droid](https://f-droid.org/packages/com.termux.api/) (Free) - Required for installation script,

* Termux:Boot [Google Play](https://play.google.com/store/apps/details?id=com.termux.boot) (Paid) | [F-Droid](https://f-droid.org/packages/com.termux.boot/) (Free) - Required for installation script.


####  2.3.2. <a name='Installjml'></a>Install jml
##### Manually
Just clone this github repo and do whatever you want. You don't need to install `Termux:API` and `Termux:Boot` to just run jml as a python script.
##### Via installation script
Below command runs an installation script that will download jml and setup auto boot so you won't have to run jml manually each time your battery dies. Run `Termux:Boot` once to enable its features and then open `Termux` and paste this command:

```
curl -O https://raw.githubusercontent.com/szyminson/jsos-msg-lookup/master/termux-install.sh & sh termux-install.sh
```
To access running jml after your phone's restart wait for the notification: 
```
jml started in tmux in termux!
```
and tap on it. Then run `tmux attach` command and you should see jml running. 
##  3. <a name='Credentialsimportingorder'></a>Credentials importing order
Importance hierachy:
```
environment variables > .env file > .creds file > ask for credentials
```
###  3.1. <a name='Example'></a>Example
If you want to input your credentials manually, you cannot have any jml related environment variables set and you have to delete .env and .creds files if they exist.

##  4. <a name='Modes'></a>Modes
For now you can run jml in 3 modes:

###  4.1. <a name='Testmode'></a>Test mode
You can use this mode to verify if jml works well and to get sample emails. Every minute you should receive (as test messages) 3 emails with 3 newest (not only unread) messages retrieved from your JSOS inbox. 

###  4.2. <a name='Normalmode'></a>Normal mode
Default mode. Behaviour of jml running this mode is described in [*Description*](#Description) part of this readme. If you provide jml with a webhook, additional alerts will be sent to webhook's URL. More about alerts [here](#Webhooksandalerts).

###  4.3. <a name='Webhookmode'></a>Webhook mode
Want to receive JSOS messages in json format? Got you covered! In this mode all messages are sent along with alerts to provided webhook's URL instead of email. Sky is the limit! You can use an existing messaging app with webhook functionality (I personally recommend [Keybase](https://keybase.io)) or create your own app to process received data.

##  5. <a name='Webhooksandalerts'></a>Webhooks and alerts
For now, if you want to receive alerts from jml you have to provide it with a webhook. Just like credentials, you can add your webhook in `.env` file (check `.env.example`) or you'll be asked for it after typing your credentials in jml. If you choose to save credentials, webhook URL will be encrypted and saved too. 
###  5.1. <a name='Erroralert'></a>Error alert
This alert is sent to the webhook when jml encounters 10 or more errors in a row.
###  5.2. <a name='Workingalert'></a>Working alert
This alert is sent when jml starts working properly again after sending Error alert.
###  5.3. <a name='JSONparameters'></a>JSON parameters
Example JSON data that jml sends to webhook. As you can see below, *msg* field is a markdown formatted string ready to be displayed. I've added this field for purpose of displaying alerts in [Keybase](https://keybase.o) app using their webhook chat bot.
####  5.3.1. <a name='Alert'></a>Alert
```json
{
    "type": "alert",
    "author": "jml",
    "author_email": "None",
    "title": "Alert title",
    "body": "Alert body",
    "errors": 10,
    "msg": "*Alert title*\nAlert body\n___"
}
```
####  5.3.2. <a name='Message'></a>Message
Only in webhook mode!
```json
{
    "type": "message",
    "author": "Nowak Jan",
    "author_email": "jan.nowak@pwr.edu.pl",
    "title": "Message title",
    "body": "Message body",
    "msg": "Nowak Jan\n*Message title*\n\nMessage body\n___"
}
```