# -*- coding=utf-8
import os
import tarfile,zipfile,zlib,gzip
print(os.listdir())
os.makedirs(os.getcwd()+'/test')
'''
with zipfile.ZipFile("myzip.zip", mode='w', compression = zipfile.ZIP_DEFLATED) as myzip:
	myzip.write('函数.md')
	myzip.write('Bookmark.md')
	print(os.listdir())
	myzip.printdir()
	myzip.extractall(path=os.getcwd()+"/test")
	print(os.listdir(os.getcwd()+"/test"))
'''
with tarfile.open("mytar.tar.gz",mode='w:gz') as mytar:
	for root,dir,files in os.walk(os.getcwd()):
        for file in files:
                fullpath = os.path.join(root,file)
                mytar.add(fullpath)
	print(os.listdir())
	mytar.list()
	mytar.extractall(path=os.getcwd()+"/test")
	print(os.listdir(os.getcwd()+"/test"))