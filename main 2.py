# -*- coding=utf-8
from qcloud_cos import CosConfig
from qcloud_cos import CosS3Client
import requests
import time
import os
import tarfile, gzip
import hashlib
import json

# VERSION: 1.1.3

try:
	response = eval(requests.get("https://service-2r0wxt44-1302691955.gz.apigw.tencentcs.com:443/release/CryingClouds_sts-1612316690").text)
	secret_id = response['Credentials']['TmpSecretId']
	secret_key = response['Credentials']['TmpSecretKey']
	token = response['Credentials']['Token']
	region = 'ap-guangzhou'
	scheme = 'https'
	config = CosConfig(Region=region, SecretId=secret_id, SecretKey=secret_key, Token=token, Scheme=scheme)
	client = CosS3Client(config)
except Exception as e:
	print("[!] Unable to initialize program: {}: {}".format(e.__class__.__name__,e))

def count_str(string):
	half = full = 0
	for i in string:
				codes = ord(i)
				if codes <= 126:
					half +=1
				else:
					full +=1
	return half,full
def compress(paths, id):  # path:list, id:str
	with tarfile.open("{}/{}.tar.gz".format(os.getcwd(), id), mode='w:gz') as tar:
		for path in paths:
			if os.path.isdir(path):
				for root, dir, files in os.walk(path):
					for file in files:
						divide_root = root.partition(path)
						outpath = divide_root[1].rpartition("/")[2] + divide_root[2] + "/" + file
						fullpath = os.path.join(root, file)
						tar.add(fullpath, outpath)
			elif os.path.isfile(path):
				tar.add(path, os.path.basename(path))
		printing=""
		total_size = max_half = max_full = 0
		for Info in tar.getmembers():
			str_count = count_str(Info.name)
			if str_count[0] > max_half:
				max_half = str_count[0]
			if str_count[1] > max_full:
				max_full = str_count[1]
			total_size += Info.size
		for Info in tar.getmembers():
			if Info.size / 1024**3 >= 1:
				str_count = count_str(Info.name)
				half = max_half - str_count[0]
				full = max_full - str_count[1]
				printing += "{}{}  \t{}GB\n".format(Info.name,' '*half+'　'*full,round(Info.size*1000/1024**3)/1000)
			elif Info.size / 1024**2 >= 1:
				str_count = count_str(Info.name)
				half = max_half - str_count[0]
				full = max_full - str_count[1]
				printing += "{}{}  \t{}MB\n".format(Info.name,' '*half+'　'*full,round(Info.size*1000/1024**2)/1000)
			elif Info.size / 1024 >= 1:
				str_count = count_str(Info.name)
				half = max_half - str_count[0]
				full = max_full - str_count[1]
				printing += "{}{}  \t{}KB\n".format(Info.name,' '*half+'　'*full,round(Info.size*1000/1024)/1000)
			else:
				str_count = count_str(Info.name)
				half = max_half - str_count[0]
				full = max_full - str_count[1]
				printing += "{}{}  \t{}B\n".format(Info.name,' '*half+'　'*full,round(Info.size*1000)/1000)
		half = max_half - 4
		full = max_full
		print_title="\nName{}  \tSize\n".format(' '*half+'　'*full)
		printing = print_title + printing
		if total_size / 1024**3 >= 1:
			total_size = "{}GB".format(round(total_size*1000/1024**3)/1000)
		elif total_size / 1024**2 >= 1:
			total_size = "{}MB".format(round(total_size*1000/1024**2)/1000)
		elif total_size / 1024 >= 1:
			total_size = "{}KB".format(round(total_size*1000/1024)/1000)
		else:
			total_size = "{}B".format(total_size)
		print(printing+"\n"+"TotalSize: "+total_size)
		return f"{os.getcwd()}/{id}.tar.gz", printing, total_size


def decompress(tarpath, id, outpath):
	with tarfile.open(tarpath, mode='r:gz') as tar:
		tar.extractall(path=outpath + "/" + id)

def hash_sha256(data, salt):
	if data != None:
		hash_data = hashlib.sha256(salt.encode("utf-8"))
		hash_salt = hashlib.sha256(data.encode("utf-8"))
		hash = hash_data.hexdigest()+hash_salt.hexdigest()
		return hashlib.sha256(hash.encode('utf-8')).hexdigest()
	else:
		return None

def upload_files(upload_paths=[os.getcwd() + "/u",], expiration=864000, key=None, msg=None):
	time_stamp = time.time()
	id = str(int(time_stamp) % 1000000)
	due = str(int(time_stamp) + expiration)  #10days
	key_hash=hash_sha256(key,"cry?ing!"+str(id)+"cloud&s")
	try:
		CheckId = client.list_objects(Bucket='cryingclouds-1302691955', Prefix='public/' + id)
		if 'Contents' in CheckId or expiration >= 1000000:
			id = str(int(time_stamp * 100 % 100000000))
		result = compress(upload_paths, id)
		tar_path = result[0]
		start_time = time.time()
		upload_file = client.upload_file(
			Bucket='cryingclouds-1302691955',
			LocalFilePath=tar_path,
			Key='public/{}_{}/{}'.format(id, due, os.path.basename(tar_path)),
			MAXThread=8,
			ServerSideEncryption='AES256',
			Metadata={'x-cos-meta-key': key_hash,})
		completion_time = time.time()
		os.remove(tar_path)
	except Exception as e:
		return "[!] Unable to upload files: {}: {}".format(e.__class__.__name__, e)
	info={'printing':result[1],"total_size":result[2]}
	if msg!= None:
		info['msg']=msg
	try:
		with open(os.path.dirname(tar_path)+"/Info.json","w+",encoding='utf-8') as Info:
			json.dump(info,Info)
		upload_file = client.upload_file(
		Bucket='cryingclouds-1302691955',
		LocalFilePath=os.path.dirname(tar_path)+"/Info.json",
		Key='public/{}_{}/{}'.format(id, due, "Info.json"),
		MAXThread=8,
		ServerSideEncryption='AES256')
		os.remove(os.path.dirname(tar_path)+"/Info.json")
	except Exception as e:
		return "[!] Unable to add message: {}: {}".format(e.__class__.__name__, e)
	return id, completion_time - start_time, info

def check_id_key(id, key):
	try:
		CheckId = client.list_objects(Bucket='cryingclouds-1302691955', Prefix='public/' + id + '_')
		if 'Contents' in CheckId:
			key_hash = hash_sha256(key,"cry?ing!"+str(id)+"cloud&s")
			head=client.head_object('cryingclouds-1302691955',CheckId['Contents'][0]['Key'])
			if 'x-cos-meta-key' not in head:
				return "True", CheckId
			else:
				if key_hash == head['x-cos-meta-key']:
					return "True", CheckId
				else:
					return "[!] Invalid Password"
		else:
			return "[!] Invalid AccessCode"
	except Exception as e:
		return "[!] Unable to download files: {}: {}".format(e.__class__.__name__, e)

def download_files(id, CheckId, download_path=os.getcwd(), crc_check=False):
	tar_path = download_path + "/" + id + ".tar.gz"
	try:
		start_time = time.time()
		download_file = client.download_file(
			Bucket='cryingclouds-1302691955',
			Key=CheckId['Contents'][0]['Key'],
			DestFilePath=tar_path,
			PartSize=20,
			MAXThread=8,
			EnableCRC=crc_check)
		completion_time = time.time()
		decompress(tar_path, id, download_path)
		os.remove(tar_path)
		Info=get_info(path=download_path,CheckId=CheckId,crc_check=crc_check)
		if "[!]" not in Info:
			info = Info
		else:
			return Info
		return completion_time - start_time,info
	except Exception as e:
		return "[!] Unable to download files: {}: {}".format(e.__class__.__name__, e)

def get_info(path, CheckId, crc_check=False):
	try:
		download_file = client.download_file(
		Bucket='cryingclouds-1302691955',
		Key=CheckId['Contents'][1]['Key'],
		DestFilePath=path+'/Info.json',
		PartSize=20,
		MAXThread=8,
		EnableCRC=crc_check)
		with open(path+'/Info.json','r',encoding='utf-8') as Info:
			info = json.load(Info)
		os.remove(path+'/Info.json')
		return info
	except Exception as e:
		return "[!] Unable to get information: {}: {}".format(e.__class__.__name__, e)
	
if __name__ == '__main__':
	print("CryingClouds")
	while True:
		mode = input("Mode: ")
		if mode == "1":
			paths = []
			msg = None
			key = None
			expiration=864000
			print("SEND")
			while True:
				command = input("Command: ")
				if os.path.exists(os.path.abspath(command)) and os.path.abspath(command) not in paths and command != '':
					if os.path.isdir(os.path.abspath(command)) == True and not os.listdir(os.path.abspath(command)):
						print("[!] The directory is empty")
					else:
						paths.append(os.path.abspath(command))
						print("\nItems:")
						for path in paths:
							print(path)
						print("")
				elif command == "u":
					if os.path.exists(os.getcwd()+'/u') == False:
						os.mkdir(os.getcwd()+'/u')
						print("Folder created: "+os.getcwd()+'/u')
					elif os.listdir(os.getcwd()+"/u") and os.getcwd()+"/u" not in paths:
						paths.append(os.getcwd()+'/u')
						print("\nItems:")
						for path in paths:
							print(path)
						print("")
				elif command == "1":
					if paths:
						upload = upload_files(paths,expiration=expiration,msg=msg,key=key)
						if "[!]" not in upload:
							print("Upload completed in {}s\nAccessCode: {}\n".format(round(upload[1]*100)/100,upload[0]))
							break
						else:
							print(upload)
					else:
						print("[!] No such file or directory")
				elif command == "2":
					key = input("Password: ")
				elif command == "3":
					msg = input("Message: ")
				elif command == "4":
					duration = input("ExpirsAfter(1~10days): ")
					if duration.isdigit() or (duration.split(".")[0].isdigit() and duration.split(".")[1].isdigit()):
						if float(duration)<=10 and float(duration)>0:
							expiration = int(float(duration)*24*60*60)
						else:
							print("[!] Invalid ExpirsAfter")
					else:
						print("[!] Invalid ExpirsAfter")
				elif command == "0":
						print("[*] Cancel")
						break
				else:
					print("[!] No such command, file or directory")
		elif mode == "2":
			key = None
			crc_check = False
			download_path = os.getcwd()
			print("RECEIVE")
			while True:
				id = input("AccessCode: ")
				check = check_id_key(id=id, key=key)
				if check != "[!] Invalid AccessCode":
					break
				else:
					print(check)
			if check == "[!] Invalid Password":
				key = input("Password: ")
				check = check_id_key(id=id, key=key)
			while check == "[!] Invalid Password":
				print(check)
				key = input("Password: ")
				check = check_id_key(id=id, key=key)
			if check[0] == "True":
				info = get_info(download_path,CheckId=check[1])
				print(info["printing"])
				print("TotalSize: "+info["total_size"])
				if 'msg' in info:
					print("Message: "+info['msg'])
				while True:
					command = input("Command: ")
					if command == "1":
						download=download_files(id=id, CheckId=check[1],download_path=download_path)
						if "[!]" not in download:
							print('\nDownload completed in {}s'.format(round(download[0]*100)/100))
							print(f"Path: {download_path}/{id}\n")
							break
						else:
							print(download)
					elif command == "2":
						download_path = os.path.abspath(input("DestFilePath: "))
						if os.path.exists(download_path) == False:
							print("[!] No such directory")
					elif command == "0":
						print("[*] Cancel")
						break
					else:
						print("[!] No such command")
			else:
				print(check)
		else:
			print("[!] No such mode")