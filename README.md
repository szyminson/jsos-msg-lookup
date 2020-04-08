# JSOS message lookup
Read JSOS messages straight from your email client!

## Description
JSOS message lookup aka *jml* checks your SMAIL inbox every minute using SSL IMAP and python scheduler. If there is an **unread** email from Edukacja.CL about a new message waiting for you on JSOS, jml logs into your JSOS account, just like you would do it in your browser (using HTTP requests) and retrieves new message's title, body and author. Then a new email message containing all retrieved data is sent to your SMAIL inbox using SMTP TLS.  

## Usage
Tested on Python `3.6.9` and `3.7.3`. 

#### Note
Remember to install required packages before running jml: 
```
$ pip3 install -r requirements.txt
```

### The most secure way
Just run jml:
```
$ python3 jml.py
```
It will ask you for your JSOS and SMAIL credentials.

#### Saving ecnrypted credentials
After providing jml with your credentials you will be asked if you want to save your credentials. If you decide to do it, you'll be prompted to provide an encryption key. AES256 CBC is used for encryption. Next time you run the jml it will only ask you for the encryption key to decrypt stored credentials. 

#### Deleting saved credentials
Delete `.creds` file from jml's directory.

### Less secure but easier to automate way
You can optionally provide jml with your credentials using environment variables. Place `.env` file constructed as `.env.example` shows in jml's directory or export your env variables before running jml.

## Credentials loading order
Importance hierachy:
```
environment variables > .env file > .creds file > ask for credentials
```
### Example
If you want to input your credentials manually, you cannot have any jml related environment variables set and you have to delete .env and .creds files if they exist.

## Modes
For now you can run jml in 2 modes:

### Test mode
You can use this mode to verify if jml works well and to get sample emails. Every minute you should receive (as test messages) 3 emails with 3 newest (not only unread) retrieved messages from your JSOS inbox. 

### Normal mode
Default mode. Behaviour of jml running this mode is described in *Description* part of this readme.
