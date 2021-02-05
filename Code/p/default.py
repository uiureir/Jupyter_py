import os
import tarfile,zipfile,zlib,gzip
print(os.listdir())
os.makedirs('/box/myzip')
'''
with zipfile.ZipFile("/box/mzip.zip", mode='w', compression = zipfile.ZIP_DEFLATED) as myzip:
	myzip.write('default.py')
	myzip.write('default(2).py')
	print(os.listdir())
	myzip.printdir()
	myzip.extractall(path="/box/myzip")
	print(os.listdir("/box/myzip"))
'''
with tarfile.open("/box/mtar.tar.gz",mode='w:gz') as mytar:
	mytar.add('default.py')
	mytar.list()