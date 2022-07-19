import httpx,time,datetime
from translate import Translator
import hmac
import hashlib
import base64
import urllib.parse

def get_cve():
    risk_like = ['CRITICAL', 'HIGH', 'MEDIUM']  # 关注的威胁级别，可添加
    care = 1  # 0表示只接收关注组件的漏洞，1表示所有组件的高危漏洞
    url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    now = datetime.datetime.now()
    ago = now-datetime.timedelta(minutes=3)#3
    pubStartDate = datetime.datetime.strftime(ago, "%Y-%m-%dT%H:%M:%S:000 UTC-08:00")
    pubEndDate = datetime.datetime.strftime(now, "%Y-%m-%dT%H:%M:%S:000 UTC-08:00")

    if care == 1:
        for risk in risk_like:
            params = {'pubStartDate': pubStartDate,'pubEndDate': pubEndDate,'cvssV3Severity': risk}
            with httpx.Client(params=params) as client:
                res = client.get(url).json()
            if res['totalResults'] > 0:
                res_content(res)

        
def res_content(res):
    content = ''

    for i in range(res['totalResults']):
        id = '漏洞编号：' + res['result']['CVE_Items'][i]['cve']['CVE_data_meta']['ID']+'\n'
        pubdate = '公开日期：' + res['result']['CVE_Items'][i]['publishedDate']+'\n'
        try:
            baseSeverity = '<font color="warning">漏洞等级：</font>' + res['result']['CVE_Items'][i]['impact']['baseMetricV3']['cvssV3']['baseSeverity']
            score = '<font color="warning">CVSSV3</font>：'+str(res['result']['CVE_Items'][i]['impact']['baseMetricV3']['cvssV3']['baseScore'])+'\n'
        finally:
            description = res['result']['CVE_Items'][i]['cve']['description']['description_data'][0]['value']
            description = translat(description)#翻译
            description = '漏洞描述：<font color=\"info\">' +description +'</font>\n'
            content = '**              【新增漏洞告警】**\n'+id +pubdate + baseSeverity+' '+score+description
            DingDing(content)#发送到钉钉

def translat(context): #翻译描述信息
        translator = Translator(to_lang="chinese")
        translation = translator.translate(context)
        return translation

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
    webhook = 'https://oapi.dingtalk.com/robot/send?access_token='
    url=webhook+'&timestamp='+timestamp+'&sign='+sign
    json={"msgtype": "markdown","text": msg,"isAtAll": True}
    httpx.post(url, json=json, headers=head, verify=False)
    # r=httpx.post(url,json=json,headers=head,verify=False)
    #print(r.text)

def main():
    while 1:
        get_cve()
        time.sleep(60 * 5)

if __name__ == "__main__":
    main()
