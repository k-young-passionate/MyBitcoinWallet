import ecdsa
import hashlib
import random
import os
import requests

from cryptos import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
from PIL import Image
from io import BytesIO

pk_global = ""
pw_global = ""
net = 1
c = 1
pw = 0
accountid = "default"

def fileexists(path):
	if os.path.exists(path) :
		return -1
	else :
		return 0

def createPassword ():
	cnt = 0
	if fileexists('./accounts/' + accountid) :
		print("Account already exists");
		return -1;
	f = open('./accounts/'+accountid, 'w')
	while True:
		if cnt == 3:
			print("\nAccount generation failed.\n")
			return -1
		password = input("Input Password: (\"exit\" to exit) (" + str((3-cnt)) +" trial left)" )
		if password == "":
			print("\nInput password please.\n")
			cnt += 1
		elif password == "exit":
			return -1;
		else:
			break
	confirmPw = input("Input Password again: (\"exit\" to exit)")
	if(confirmPw == "exit"):
		return -1
	if password == confirmPw :
		print("\nYou just have made your own password!\n")
		f.write(hashlib.sha256(password.encode('utf-8')).digest().hex())
		f.close()
		return 0
	else :
		print("\nTwo different passwords!\n")
		f.close()
		return -1


def confirmPassword ():
	global pw
	f = open("./accounts/"+accountid, "r")
	password = input("input Password: ")
	string = f.readline()
	string2 = hashlib.sha256(password.encode('utf-8')).digest().hex() 
	if string == string2:
		pw = password
		f.close()
		return password 
	else :
	 	f.close()
	 	return -1 


def createPrivateKey ():
	f = open("./privatekeys/"+accountid+"_"+str(net)+"_"+"privateKey.pem", 'wb')
	private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
	e_pk = encrypt_AES(pad(private_key.to_pem(), 16), confirmPassword())
	f.write(e_pk)
	f.close()
	return private_key


def getPrivateKey ():
	global pw
	if pw == 0:
		password = confirmPassword()
	else :
		password = pw
	if password != "":
		f = open("./privatekeys/"+accountid+"_"+str(net)+"_"+"privateKey.pem", 'rb')
		ek = f.read()
		privateKey = ecdsa.SigningKey.from_pem(unpad(decrypt_AES(ek, pw), 16))
		f.close()
		return privateKey
	else :
		return -1


def encrypt_AES(pk, pw):
	key = hashlib.md5(pw.encode('utf-8')).digest().hex()
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode, IV=IV)

	passKey = encryptor.encrypt(pk)

	return passKey


def decrypt_AES(pk, pw):
	key = hashlib.md5(pw.encode('utf-8')).digest().hex()
	IV = 16 * '\x00'
	mode = AES.MODE_CBC
	encryptor = AES.new(key, mode, IV=IV)

	passKey = encryptor.decrypt(pk)

	return passKey


def getAddress (private_key):
	public_key = c.privtopub(private_key)
	address = c.pubtoaddr(public_key)

	return address


def sendBitcoin (to_address, amount, memo):
	try :
		c.send(getPrivateKey(), to_address, int(amount))
	except Exception:
		print("\nAddress is wrong or your balance is not enough.")

def showMyWalletInfo (address):
	transaction = c.history(address)
	print("Hash160: " + transaction['hash160'])
	print("Address: " + transaction['address'])
	print("n_tx: " + str(transaction['n_tx']))
	print("total_received: " + str(transaction['total_received']))
	print("total_sent: " + str(transaction['total_sent']))
	print("final_balance: " + str(transaction['final_balance']))
	print("\nMy UTXO: ")
	txs = transaction['txs'];
	cnt = 1
	for x in range(len(txs)):
		t = txs[x]
		tt = t['out']
		for y in range(len(t['out'])):
			if tt[y]['spent'] == False and tt[y]['addr'] == address:
				print("transaction #"+str(cnt))
				cnt += 1
				print ("ver: "+str(t['ver']))
				print("inputs: " + str(t['inputs']))
				print("weight: " + str(t['weight']))
				print("relayed_by: " + t['relayed_by'])
				print("out: " + str(t['out']))
				print("lock_time: " + str(t['lock_time']))
				print("result: " + str(t['result']))
				print("size: " + str(t['size']))
				print("time: " + str(t['time']))
				print("tx_index: " + str(t['tx_index']))
				print("vin_sz: " + str(t['vin_sz']))
				print("hash: " + t['hash'])
				print("vout_sz: " + str(t['vout_sz']))
				print()


def showTransactionHistory (address):
	transaction = c.history(address)
	print("Hash160: " + transaction['hash160'])
	print("Address: " + transaction['address'])
	print("n_tx: " + str(transaction['n_tx']))
	print("total_received: " + str(transaction['total_received']))
	print("total_sent: " + str(transaction['total_sent']))
	print("final_balance: " + str(transaction['final_balance']))
	print()
	txs = transaction['txs'];
	for x in range(len(txs)):
		t = txs[x]
		if t['out'][0]['addr'] == address:
			print("In")
		else:
			print("Out")
		print("transaction #"+str(x))
		print ("ver: "+str(t['ver']))
		print("inputs: " + str(t['inputs']))
		print("weight: " + str(t['weight']))
		print("relayed_by: " + t['relayed_by'])
		print("out: " + str(t['out']))
		print("lock_time: " + str(t['lock_time']))
		print("result: " + str(t['result']))
		print("size: " + str(t['size']))
		print("time: " + str(t['time']))
		print("tx_index: " + str(t['tx_index']))
		print("vin_sz: " + str(t['vin_sz']))
		print("hash: " + t['hash'])
		print("vout_sz: " + str(t['vout_sz']))
		print()
	return 0

def exitProgram():
	print("Wallet terminated.")
	return 0

def chooseNetwork():
	global net
	global c
	while True:
		network = input("Choose 'mainnet' or 'testnet' (to exit, type 'exit'): ")
		if network == "mainnet" or network == 'm' or network == 'Mainnet' or network == 'main net' or network == 'Main net':
			c = Bitcoin(mainnet=True)
			net = 1
			break
		elif network == "testnet" or network == 'Testnet' or network == 'test net' or network == 'Test net' or network == 't':
			c = Bitcoin(testnet=True)
			net = 2
			break
		elif network == 'exit':
			net = -1
			break
		else :
			print("You typed wrong.")


def generateQR(addr, amount, message):
	url = "https://chart.googleapis.com/chart?chs=225x225&chld=L|2&cht=qr&chl=bitcoin:"+addr+"?amount="+amount+"%26message="+message
	res = requests.get(url)
	f = open('./qr'+addr+'_'+amount+'.png', 'wb');
	f.write((res.content));
	f.close();
	img = Image.open(BytesIO(res.content))
	img.show()
	


def main ():

	global accountid
	if not os.path.exists('./accounts'):
		os.makedirs('./accounts')
	if not os.path.exists('./privatekeys'):
		os.makedirs('./privatekeys')
	
	while True:
		account = input("Choose 'Log in' or 'Sign up' (to exit, type 'exit'): ")
		if account == 'Sign up' or account == 'Signup' or account == 'signup' or account == 'sign up' or account == 's':
			cnt = 0;
			while True:
				if cnt == 3:
					print("\nID generation failed.\n")
					break;
				accountid = input("Your account ID: (" + str((3-cnt)) +" trial left)" )
				if accountid == "":
					print("\nInput ID please.\n")
					cnt += 1
				else:
					break
			if cnt == 3:
				continue

			exists = os.path.isfile('./accounts/'+accountid)
			if exists:
				print("\nID already exists!\n")
				continue
			else :
				passresult = createPassword()
				if passresult == 0:
					print("\nYour account has been created!\n")
					continue
				else :
					print("\nRetry again!\n")
					continue
	
		elif account == 'Log in' or account == 'Login' or account == 'login' or account == 'log in' or account == 'l':
			accountid = input("Your account ID: ")
			exists = os.path.isfile('./accounts/'+accountid)
			if exists:
				confirmResult = confirmPassword()
				if confirmResult == -1:
					print("\nAccess Denied\n")
					continue
				print("\nAccess Accepted\n")
				chooseNetwork()
				if net == -1:
					exitProgram()
					return 0
			else :
				print("\nID doesn't exist!\n")
				continue
		elif account == 'exit':
			exitProgram()
			return 0
		else:
			print("\nYou typed wrong.\n")
			continue

		if not os.path.exists("./privatekeys/"+accountid+"_"+str(net)+"_"+"privateKey.pem"):
			pk = createPrivateKey()
			print("\nYour privatekey is " + pk.to_string().hex() +"\nYou should remember this just in case!!!!")
			print("Your wallet address is " + getAddress(pk) + "\n")
		else :
			print("\nYour wallet address is " + getAddress(getPrivateKey()) + "\n")

		while True:
			try:
				action = int(input("Choose your action\nTo see your address, type '1'\nTo See my wallet info, type '2'\nTo see transaction history, type '3'\nTo send Bitcoin, type '4'\nTo generate a QR code for your Bitcoin address, type '5'\nTo exit this program, type '0'\n"))
			except Exception:
				print("\nYou typed wrong.\n")
				continue
			if action == 1:
				print("\nYour wallet address is " + getAddress(getPrivateKey()) + "\n")
			elif action == 2:
				showMyWalletInfo(getAddress(getPrivateKey()))
			elif action == 3:
				addr = input("Type the address that you want to see the transactions of: ")
				try:
					showTransactionHistory(addr)
				except Exception:
					print("\nWrong address!\n")
			elif action == 4:
				addr = input("Type the address that you want to send Bitcoin: ")
				try:
					print("1 bitcoin = 100,000,000 Satoshi")
					am = int(input("Type the amount of Bitcoin you want to send(Satoshi): "))
				except Exception:
					print("\nError occured!!! You should input number here.\n")
					continue
				memo = input("Type memo: ")
				sendBitcoin(addr, am, memo)
			elif action == 5:
				print("1 bitcoin = 100,000,000 Satoshi")
				amt = input("Type the amount of Bitcoin you want to get(Satoshi): ")
				memo = input("Type a memo you want to generate with: ")
				generateQR(getAddress(getPrivateKey()), amt, memo)
			elif action == 0 :
				exitProgram()
				break
			else :
				print("You typed wrong.")
				continue

		return 0
	
	return 0

main()

