import os
import requests

def upload(path, url, headers):
    upload_url = url + "files"
    files = {"file" :(
            os.path.basename(path),
            open(os.path.abspath(path), "rb"))}
    res = requests.post(upload_url, headers = headers, files = files)
    if res.status_code == 200:
        file_id = res.json().get("data").get("id")
        print("successfully upload PE file: OK")
    else:
        print(":(")

    return file_id

def analyse(url, headers, fileID):
    analysis_url = url + "analyses/" + fileID
    res = requests.get(analysis_url, headers = headers)
    if res.status_code == 200:
        result = res.json()
        status = result.get("data").get("attributes").get("status")
        if status == "completed":
            stats = result.get("data").get("attributes").get("stats")
            print ("malicious: " + str(stats.get("malicious")))
            print ("undetected : " + str(stats.get("undetected")))
            print ("successfully analyse: OK")
    else:
        print ("failed to get results of analysis :(")
        print ("status code: " + str(res.status_code))            

def main ():
VT_API_KEY= "fffc3cbd847150e9f618b62086ab5f30ccf016e1196d8206243e07d85a4788b3"
VT_API_URL= "https://www.virustotal.com/api/v3/ "
headers= {"x-apikey" : VT_API_KEY,
            "User-Agent" : "vtscan v.1.0",
            "Accept-Encoding" : "gzip, deflate",
        }
scan_ID=upload()
