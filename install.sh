#!/bin/bash
# 'wget -qO- https://raw.githubusercontent.com/tbscode/tvault/main/install.sh | bash'

mkdir -p /home/$USER/.config/tvault
cd /home/$USER/.config/tvault
if [ -d "venv" ]; then
    rm -rf venv
fi

python3 -m venv venv
source venv/bin/activate
pip install git+https://github.com/tbscode/tvault

echo "alias tvault='/home/$USER/.config/tvault/venv/bin/tvault'" >> /home/$USER/.bashrc