import json
import os
import shutil
import sys
from time import sleep
from zipfile import ZipFile


def convert(x):
    if x.startswith("/bin/sh -c #(nop)"):
		# remove it
        x = x[len("/bin/sh -c #(nop)"):]
    elif x.startswith("/bin/sh -c"):
		# remove this and add RUN
        x = x[len("/bin/sh -c"):]
        x = "RUN" + x
    return x.strip()

#x = "/bin/sh -c #(nop)  CMD [\"mongod\"]"
#x = "/bin/sh -c #(nop)  EXPOSE 27017"
#x = "/bin/sh -c #(nop)  ENV MONGO_VERSION=6.0.1"
#x = "/bin/sh -c set -x  && export DEBIAN_FRO"
#x = convert(x)
#print(x)




print("[INFO] Name of the image : ", sys.argv[1])

manifest = json.load(open(os.path.join(sys.argv[1], "manifest.json")))
data = json.load(open(os.path.join(sys.argv[1], manifest[0]['Config'])))


index = 0
layers = []
command = ""
for x in data['history']:
    # print(x['created_by'])
    y = convert(x['created_by'])
    # print(y)
    if 'author' in x.keys() and x['author'] == 'AWS Lambda':
        if 'empty_layer' in x.keys() and x['empty_layer']:
            continue
        index = index + 1
        continue
    if 'empty_layer' in x.keys():
        if y.startswith('CMD'):
            command = y
        continue
    if y.startswith('COPY'):
        layers.append(manifest[0]['Layers'][index])
    if y.startswith('ADD'):
        layers.append(manifest[0]['Layers'][index])
    index = index + 1
 
for x in layers:
    print("[INFO]", os.path.join(sys.argv[1], x))

print("[INFO] Command is", command)
main = command.split(" ")[1][2:-2].split(".")[0] + '.py'
print("[INFO] Main file is", main)
# for x in answer:
#     with ZipFile(os.path.join(sys.argv[1], x), "r") as zip_ref:
#         zip_ref.extractall(os.path.join(sys.argv[1],x[:-len('/layer.tar')]))

if not os.path.exists('output/'):
    os.mkdir('output')

req_dest = ""

for x in layers:
    print("[INFO] unzip the above mentioned layers")
    while not os.path.exists(os.path.join(sys.argv[1], x[:-len('.tar')])):
        continue
    sleep(2)
    print("[INFO] layer.tar has been unzipped")
    for dirpath, dirnames, filenames in os.walk(os.path.join(sys.argv[1], x[:-len('.tar')])):   
        dirpath_new = dirpath.replace(os.path.join(sys.argv[1],x[:-len('.tar')]), 'output')
        for dirname in dirnames:
            if not os.path.exists(os.path.join(dirpath_new, dirname)):
                os.mkdir(os.path.join(dirpath_new,dirname))
        for filename in filenames:
            if filename == 'requirements.txt':
                req_dest = os.path.join(dirpath_new,filename)
            if filename == main:
                main_dest = os.path.join(dirpath_new,filename)
            shutil.copyfile(os.path.join(dirpath,filename), os.path.join(dirpath_new,filename))

print("[INFO] Destination of main file is",main_dest)
print("[INFO] Destination of requirements.txt is", req_dest)
