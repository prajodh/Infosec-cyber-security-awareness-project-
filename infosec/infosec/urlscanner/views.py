from django.shortcuts import render
from . import models
import json
from numpy import append
import requests
from urllib.request import urlopen
from bs4 import BeautifulSoup
import sys
import hashlib
import json
from virus_total_apis import PublicApi as public_api
from .models import fileupload
import os
import string
import base64 
from Crypto import Random
from Crypto.Cipher import AES
import hashlib
from .program.aes import sha256,pad,unpad,encrypt,decrypt
from .models import imageupload
import mimetypes
# import os module
import os
# Import HttpResponse module
from django.http.response import HttpResponse
from django.core.files import File
import webbrowser

# Create your views here.
def urlscanner(request):
    if request.POST:
        urlq=request.POST['urlscanner']
        print(urlq)
        api_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    #res = input("enter the website:\n")
        res = urlq
        params = dict(apikey='ce67285c4e31732904d998789737b6419ef21b3dd73f4af53751fcdb8a3820b4', resource=res, scan=0)
        response = requests.get(api_url, params=params)
        if response.status_code == 200:
            result=response.json()
            print(json.dumps(result, sort_keys=False, indent=4)) 
        context={'results':result['scans'],'user':True}
        print(context)
        return render(request,'urlscanner/uscanning.html',context=context)
    
    else:
        
        return render(request,'urlscanner/uscanning.html',)

def ipaddress_scanner(request):
    if request.POST:
        ip1=request.POST['ipaddress']
        print(ip1)
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'

        params = {'apikey':'ce67285c4e31732904d998789737b6419ef21b3dd73f4af53751fcdb8a3820b4','ip':ip1}

        response = requests.get(url, params=params)
        url="http://ip-api.com/json/"+ip1
        r=requests.get(url)
        ipinfo=r.json()
        lat=ipinfo['lat']
        lon=ipinfo['lon'] 
        print('Country     : ',ipinfo['country'])
        print('Region Name : ',ipinfo['regionName'])
        print('City        : ',ipinfo['city'])
        print('Time zone   : ',ipinfo['timezone'])
        print('ISP         : ',ipinfo['isp'])
        mapurl = "https://maps.google.com/maps?q=%s,+%s" % (lat, lon)
        webbrowser.open(mapurl, new=2) 
        context={'results':response.json(),'user':True,'Country':ipinfo['country'],'RegionName' :ipinfo['regionName'],'City':ipinfo['city'],'Timezone':ipinfo['timezone'],'ISP':ipinfo['isp']}
        return render(request,'urlscanner/ipaddress.html',context=context)
    else:
        return render(request,'urlscanner/ipaddress.html')
def clickjacking(request):
    if request.POST:
        data = urlopen(str(request.POST['clickjacking']))
        headers = data.info()

        if not "X-Frame-Options" in headers:
            context={"ans":"Website is vulnerable to ClickJacking",'user':True}

        else:
            context={"ans":"Website is not Vulnerable to ClickJacking",'user':True,'links':'the links are'}
        response=requests.get(str(request.POST['clickjacking']))
        soup=BeautifulSoup(response.text,'html.parser')
        l = []
        for link in soup.find_all('a'):
            lin=link.get('href')
        
            if(lin.startswith('http')):
                l.append(lin)
        context['ans2']=l
        
        return render(request,'urlscanner/clickjacking.html',context=context)
    else:
        return render(request,'urlscanner/clickjacking.html')
def filescanner(request):
    if request.method=='POST':
        file=request.FILES['filescanner']
        document=fileupload.objects.create(file=file)
        document.save()
        api_key = "ce67285c4e31732904d998789737b6419ef21b3dd73f4af53751fcdb8a3820b4"
        content = file.read()
        md5_sum = hashlib.md5()
        md5_sum.update(content)
        digest = md5_sum.hexdigest()
        vt = public_api(api_key)
        response = vt.get_file_report(digest)
        print(json.dumps(response,sort_keys=False,indent=4))
        context={'ans':response['results']['scans'],'user':True}
        return render(request,'urlscanner/filescanner.html',context=context)
    return render(request,'urlscanner/filescanner.html')


def image_encrypt(request,filename=''):
    if request.method =='POST':
        files=request.FILES['image_encrypt']
        key=request.POST['image_encrypt']
        key = sha256(key)
        base64_file = base64.b64encode(files.read())
        enc = encrypt(base64_file,key)
        fp1 = open("encryptedfile.png",'wb')
        fp1.write(enc)
        fp1.close()
        context={'file':fp1,'user':True,}

        return render(request,'urlscanner/image.html',context)

    return render(request,'urlscanner/image.html')