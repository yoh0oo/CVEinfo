import math
import httpx,time,datetime
from pygtrans import Translate
import hmac
import hashlib
import base64
import urllib.parse
import requests

hours =6

def req_cve(index = 0,risk = ''):
    url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    now = datetime.datetime.now()
    ago = now-datetime.timedelta(hours=hours)#3
    pubStartDate = datetime.datetime.strftime(ago, "%Y-%m-%dT%H:%M:%S:000 UTC+08:00")
    pubEndDate = datetime.datetime.strftime(now, "%Y-%m-%dT%H:%M:%S:000 UTC+08:00")
    params = {'pubStartDate': pubStartDate,'pubEndDate': pubEndDate,'cvssV3Severity': risk,'startIndex':index}
    with httpx.Client(params=params, timeout=None) as client:
        res = client.get(url).json()
        return res

def get_cve(index = 0,risk_like = []):
    print(risk_like)
    risk_like = ['CRITICAL', 'HIGH', 'MEDIUM'] if len(risk_like) == 0 else risk_like  # 关注的威胁级别，可添加
    for risk in risk_like:
        res = req_cve(index=index,risk=risk)
        # print(res)
        if res['totalResults'] > 0:
            if res['totalResults'] == res['resultsPerPage']:
                res_content(res)
            else:
                for i in range(1,math.ceil(res['totalResults']/res['resultsPerPage'])):
                    req_cve(index=20*i+1,risk=risk)
            
def res_content(res):
    content = ''

    for i in range(res['totalResults']):
        id = '漏洞编号：' + res['result']['CVE_Items'][i]['cve']['CVE_data_meta']['ID']+'\n\n'
        pubdate = '公开日期：' + res['result']['CVE_Items'][i]['publishedDate']+'\n\n'
        try:
            baseSeverity = '<font color="#fba900">漏洞等级：</font>' + res['result']['CVE_Items'][i]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            score = '<font color="#fba900">CVSSV3</font>：'+str(res['result']['CVE_Items'][i]['impact']['baseMetricV3']['cvssV3']['baseScore'])+'\n\n'
        finally:
            description = res['result']['CVE_Items'][i]['cve']['description']['description_data'][0]['value']
            description = translat(description)#翻译
            description = '漏洞描述：<font color=\"#20993b\">' +description +'</font>\n\n'
            content = '# 【新增漏洞告警】\n\n'+id +pubdate + baseSeverity+' '+score+description
            DingDing(content)#发送到钉钉

def translat(context): #翻译描述信息
    client = Translate()
    text = client.translate(context)
    return text.translatedText

# 钉钉推送
def DingDing(msg):
    head = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36"
    }
    timestamp = str(round(time.time() * 1000))
    # 钉钉机器人的加签密钥
    secret = ''
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    # 钉钉机器人的Webhook
    webhook = ''
    url=webhook+'&timestamp='+timestamp+'&sign='+sign
    json={"msgtype": "markdown","markdown":{"title":"新增漏洞告警","text": msg},"isAtAll": True}
    print(json)
    requests.post(url, json=json, headers=head, verify=False)

def main():
    while 1:
        get_cve()
        time.sleep(3600 * hours)

if __name__ == "__main__":
    main()
