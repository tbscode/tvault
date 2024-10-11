#!/bin/bash
# 'wget -qO- https://raw.githubusercontent.com/tbscode/tvault/main/update.sh | bash'

mkdir -p /home/$USER/.config/tvault
cd /home/$USER/.config/tvault
if [ -d "/home/$USER/.config/tvault/venv" ]; then
    rm -rf /home/$USER/.config/tvault/venv
fi

python3 -m venv venv
source venv/bin/activate
pip install git+https://github.com/tbscode/tvault

awk '!/tvault=/' /home/$USER/.bashrc > /tmp/updated_rc && mv /tmp/updated_rc /home/$USER/.bashrc
echo "alias tvault='/home/$USER/.config/tvault/venv/bin/tvault'" >> /home/$USER/.bashrc