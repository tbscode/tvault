#!/bin/bash
# wget https://raw.githubusercontent.com/tbscode/tvault/main/install.sh -O - | bash

mkdir -p /home/$USER/.config/tvault
cd /home/$USER/.config/tvault
python3 -m venv venv
source venv/bin/activate
pip install git+https://github.com/tbscode/tvault

echo "alias tvault='/home/$USER/.config/tvault/venv/bin/tvault'" >> /home/$USER/.bashrc