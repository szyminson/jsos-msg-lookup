# jsos-msg-lookup
Read JSOS messages straight in your email client!

## Usage
### The most secure way
Just simply run the `jml.py`. It will ask you for your JSOS and SMAIL credentials.
#### Saving ecnrypted credentials
After providing jml with your credentials you will be asked if you want to save your credentials. If you decide to do it, you will be prompted to provide an encryption key. Next time you run the jml it will only ask you for the encryption key to decrypt stored credentials.
#### Deleting saved credentials
Just simply delete `.creds` file from jml's directory.

### Less secure but easier to automate way
You can optionally provide jml with your credentials using environment variables. Just use `.env` file or export your env variables before running jml.
