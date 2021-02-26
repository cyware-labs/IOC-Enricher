import sys
import requests
import time
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
import get_malicious
from abuseipdb import *
import json

template = ' {indicator} | {alert}'
enriched_data = open ('results.txt', 'w')
score_template = 'Virus Total : {vt} | AbuseIPDB {aid} | Threat Miner {tm} | Under Attack {ua}'


class Enrich (object):
    def __init__(self):
        self.otx = OTXv2 ("Enter OTX key here")
        self.vt_api = 'Enter VT API key here'
        self.ipdb = AbuseIPDB ('Enter AbuseIPDB key Here')
        self.user = 'Enter underattack username here'
        self.password = 'Enter underattack password here'
        self.vt_base_url = 'https://www.virustotal.com/'

    def enrich_otx_ip(self, indicator) -> object:
        """

        @param indicator:
        @return:
        """
        try:
            alerts = get_malicious.ip (self.otx, indicator)
            if len (alerts) != 0:
                for alert in alerts:
                    a = template.format (
                        indicator=indicator,
                        alert=alert
                    )
                    enriched_data.write (a)
                    enriched_data.write ('\n')
                    return True
            else:
                a = template.format (
                    indicator=indicator,
                    alert="No enrichment data found"
                )
                enriched_data.write (a)
                enriched_data.write ('\n')

        except Exception as e:
            return False

    def enrich_otx_hash(self, indicator) -> object:
        """

        @param indicator:
        @return:
        """
        try:
            alerts = get_malicious.file (self.otx, indicator)
            if len (alerts) != 0:
                for alert in alerts:
                    a = template.format (
                        ioc_type="Hash",
                        ioc_value=indicator,
                        ioc_source="Alienvault",
                        ioc_alert=alert
                    )
                    enriched_data.write (a)
                    enriched_data.write ('\n')
                    return True
            else:
                a = template.format (
                    ioc_type="IP",
                    ioc_value=indicator,
                    ioc_source="Alienvault",
                    ioc_alert="No enrichment data found"
                )
                enriched_data.write (a)
                enriched_data.write ('\n')

        except Exception as e:
            print ("OTX is not able to process this indicator: " + str (indicator))
            return False

    def enrich_otx_url(self, indicator) -> object:
        """

        @param indicator:
        @return:
        """
        try:
            alerts = get_malicious.url (self.otx, indicator)
            if len (alerts) != 0:
                for alert in alerts:
                    a = template.format (
                        ioc_type="URL",
                        ioc_value=indicator,
                        ioc_source="Alienvault",
                        ioc_alert=alert
                    )
                    enriched_data.write (a)
                    enriched_data.write ('\n')
                    return True
            else:
                a = template.format (
                    ioc_type="IP",
                    ioc_value=indicator,
                    ioc_source="Alienvault",
                    ioc_alert="No enrichment data found"
                )
                enriched_data.write (a)
                enriched_data.write ('\n')
        except Exception as e:
            print ("OTX is not able to process this indicator: " + str (indicator))
            return False

    def enrich_vt_url(self, url) -> object:
        """

        @param url:
        @return:
        """
        url = self.vt_base_url'vtapi/v2/url/report'
        params = {'apikey': self.vt_api, 'resource': url}
        response = requests.post (url, data=params)
        try:
            response = requests.get (url, params=params)
            response = response.json ()
            score = response['detected_referrer_samples'][0]['positives']
            time.sleep (15)
        except:
            score = 0
        return score

    def enrich_vt_ip(self, ip) -> object:
        """

        @param ip:
        @return:
        """
        url = self.vt_base_url + 'vtapi/v2/ip-address/report'
        params = {'apikey': self.vt_api, 'ip': ip}
        try:
            response = requests.get (url, params=params)
            response = response.json ()
            score = response['detected_referrer_samples'][0]['positives']
            time.sleep (15)
        except:
            score = 0
        return score

    def enrich_abuseipdb(self, indicator) -> object:
        """

        @param indicator:
        """

        ip_check = self.ipdb.check (indicator)
        score = ip_check.abuseConfidenceScore
        return score

    def enrich_underattack(self, indicator):
        """

        :type indicator: IP address
        """
        response = requests.get ('https://portal.underattack.today/api/lookup/ip/{0}'.format (indicator),
                                 auth=requests.auth.HTTPBasicAuth (self.user, self.password))
        response = response.text
        return response

    def enrich_threatminer(self, indicator):
        """

        :type indicator: IP address
        """
        response = requests.get ('https://api.threatminer.org/v2/host.php?q={0}&rt=4'.format (indicator))
        response = response.text
        return response

    def get_relations_ip(self, indicator):
        """

        :type indicator: IP address
        """
        relations = requests.get ("http://www.threatcrowd.org/searchApi/v2/ip/report/", {"ip": indicator}).text
        relations = json.loads (relations)
        print (relations)
        return relations

    def get_relations_url(self, indicator):  # need to fix
        """

        :type indicator: URL
        """
        relations = requests.get ("http://www.threatcrowd.org/searchApi/v2/domain/report/", {"domain": indicator}).text
        print (relations)

    def main(self):
        print ("[+] Welcome to IOC Enricher")
        option = int(input("Enter 1 to enrich an indicator, 2 to get relations of an indicator: "))
        if option == 1:
            indicator = str (input ("Enter IP to enrich: "))
            otx_status = self.enrich_otx_ip (indicator)
            aid_score = self.enrich_abuseipdb (indicator)
            vt_score = self.enrich_vt_ip (indicator)
            tm_response = self.enrich_threatminer (indicator)
            ua_response = self.enrich_underattack (indicator)
            a = score_template.format (vt=vt_score,
                                       aid=aid_score,
                                       tm=tm_response,
                                       ua=ua_response)
            enriched_data.write (a)
            enriched_data.write ('\n')

        if option == 2:
            indicator = str (input ("Enter IP to get relations for: "))
            relations = self.get_relations_ip (indicator)
            enriched_data.write (str (relations))
            enriched_data.write ('\n')


x = Enrich ()
x.main()
