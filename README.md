# JSOS message lookup
Read JSOS messages straight in your email client!
## Description
JSOS message lookup aka *jml* checks your SMAIL inbox every minute using imap ssl and python scheduler. If there is an **unread** email from Edukacja.CL about a new message waiting for you on JSOS jml logs into your JSOS account just like you would do it in your browser (using HTTP requests) and retireves new message's title, body and author. Then a new email message containing all retrieved data is sent to your SMAIL inbox.  

## Usage
### The most secure way
Just simply run the `jml.py`. It will ask you for your JSOS and SMAIL credentials.
#### Saving ecnrypted credentials
After providing jml with your credentials you will be asked if you want to save your credentials. If you decide to do it, you will be prompted to provide an encryption key. AES256 CBC is used for encryption. Next time you run the jml it will only ask you for the encryption key to decrypt stored credentials. 
#### Deleting saved credentials
Delete `.creds` file from jml's directory.

### Less secure but easier to automate way
You can optionally provide jml with your credentials using environment variables. Place `.env` file constructed as in `.env.example` in jml's directory or export your env variables before running jml.
