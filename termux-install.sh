#!/data/data/com.termux/files/usr/bin/sh

# Dependencies
apt update & apt install python git tmux termux-api

# Clone repo
git clone https://github.com/szyminson/jsos-msg-lookup.git ~/jml

# Python dependencies
cd ~/jml
pip install -r requirements.txt

# Setup boot script
mkdir -p ~/.termux/boot
cp termux-boot-jml ~/.termux/boot

# Done
echo "Done! Starting jml..."
./jml.py

