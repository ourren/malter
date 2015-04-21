#!/usr/bin/env python
# encoding: utf-8
# author: toby
# website: http://ourren.github.io/

import sys
import glob
import json
import requests
import urlparse
import argparse
import multiprocessing

from common.color import inBlue, inRed
from common.color import inWhite, inGreen, inYellow
from common.output import output_init, output_finished, output_add

def check(plugin, target, target_type):
    '''
    plugin: *.json
    target: ip, url
    target_type: target type
    '''
    if plugin["request"]["{0}_url".format(target_type)]:
        url = plugin["request"]["{0}_url".format(target_type)]
        url = url.format(target)
    else:
        return
    app_name = plugin['information']['name']
    category = plugin["information"]["category"]
    website = plugin["information"]["website"]
    judge_yes_keyword = plugin['status']['judge_yes_keyword']
    judge_no_keyword = plugin['status']['judge_no_keyword']
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6',
        'Host': urlparse.urlparse(url).netloc,
        'Referer': url,
    }
    if plugin['request']['method'] == "GET":
        try:
            if url.startswith('https://'):
                from requests.packages.urllib3.exceptions import InsecureRequestWarning
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                content = requests.get(url, headers=headers, verify=False).content
            else:
                content = requests.get(url, headers=headers).content
        except Exception, e:
            print inRed('\n[-] %s ::: %s\n' % (app_name, str(e)))
            return
        for i_yes_keyword in judge_yes_keyword:
            if i_yes_keyword in content:
                if judge_no_keyword != '':
                    print u"[{0}] {1}".format(category, ('%s (%s)' % (app_name, website)))
                    icon = plugin['information']['icon']
                    desc = plugin['information']['desc']
                    output_add(category, app_name, website, target, target_type, icon, desc, url)
                    break
                else:
                    for i_no_keywords in judge_no_keyword:
                        if i_no_keywords and i_no_keywords not in content:
                            print u"[{0}] {1}".format(category, ('%s (%s)' % (app_name, website)))
                            icon = plugin['information']['icon']
                            desc = plugin['information']['desc']
                            output_add(category, app_name, website, target, target_type, icon, desc, url)
                            break

        else:
            pass
    elif plugin['request']['method'] == "POST":
        post_data = plugin['request']['post_fields']
        if post_data.values().count("") != 1:
            print "The POST field can only leave a null value."
            return
        for k, v in post_data.iteritems():
            if v == "":
                post_data[k] = target
        try:
            if url.startswith('https://'):
                from requests.packages.urllib3.exceptions import InsecureRequestWarning
                requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
                content = requests.post(url, data=post_data, headers=headers, verify=False).content
            else:
                content = requests.post(url, data=post_data, headers=headers).content
        except Exception, e:
            print e, app_name
            return
        for i_yes_keyword in judge_yes_keyword:
            if i_yes_keyword in content:
                if judge_no_keyword != '':
                    print u"[{0}] {1}".format(category, ('%s (%s)' % (app_name, website)))
                    icon = plugin['information']['icon']
                    desc = plugin['information']['desc']
                    output_add(category, app_name, website, target, target_type, icon, desc, url)
                    break
                else:
                    for i_no_keywords in judge_no_keyword:
                        if i_no_keywords and i_no_keywords not in content:
                            print u"[{0}] {1}".format(category, ('%s (%s)' % (app_name, website)))
                            icon = plugin['information']['icon']
                            desc = plugin['information']['desc']
                            output_add(category, app_name, website, target, target_type, icon, desc, url)
                            break
    else:
        print u"{}:::Error!".format(plugin['request']['name'])


def main():
    reload(sys)
    sys.setdefaultencoding("utf-8")
    parser = argparse.ArgumentParser(description="Check how many malicious/spam result of IP.")
    parser.add_argument("-i", action="store", dest="ip")
    parser_argument = parser.parse_args()
    banner = '''
                        _  _
                       | || |
      _ __ ___    __ _ | || |_  ___  _ __
     | '_ ` _ \  / _` || || __|/ _ \| '__|
     | | | | | || (_| || || |_|  __/| |
     |_| |_| |_| \__,_||_| \__|\___||_|


    '''
    all_argument = [parser_argument.ip]
    plugins = glob.glob("./plugins/*.json")
    print inGreen(banner)
    print '[*] App: Malware/Spam ip online check'
    print '[*] Version: V1.0(20150420)'
    print '[*] Website: ourren.github.io'
    file_name = ""
    if all_argument.count(None) != 0:
        print '\nInput "-h" view the help information.'
        sys.exit(0)
    if parser_argument.ip:
        print inRed('\n[+] IP Checking: %s\n') % parser_argument.ip
        file_name = "ip_" + str(parser_argument.ip)
        output_init(file_name, "ip: ", str(parser_argument.ip))
    jobs = []
    for plugin in plugins:
        with open(plugin) as f:
            try:
                content = json.load(f)
            except Exception, e:
                print e, plugin
                continue
        if parser_argument.ip:
            p = multiprocessing.Process(target=check, args=(content, unicode(parser_argument.ip, "utf-8"), "ip"))
        p.start()
        jobs.append(p)
    while sum([i.is_alive() for i in jobs]) != 0:
        pass
    for i in jobs:
        i.join()
    output_finished(file_name)


if __name__ == '__main__':
    main()
