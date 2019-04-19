#!/bin/bash

pip3 install ecdsa
pip3 install hashlib
pip3 install requests
pip3 install cryptos
pip3 install crypto
pip3 install pycrypto
pip3 install pillow
mv Crypto ./env/lib/python3.6/site-packages

python3 ./SKYBitcoinWallet.py
