from bs4 import BeautifulSoup
import urllib.request
import time
import csv
import sys
import threading
import argparse
import logging
import os
import re

thread_cnt = 12
input  = './in/nist-cve.txt'
output = './in/nist-cve.csv'

input = os.path.join(os.path.dirname(os.path.abspath(__file__)), input)
output = os.path.join(os.path.dirname(os.path.abspath(__file__)), output)

cve_obj_array = []

def save_csv(cve_array, filename):
    fieldnames = ['CVE_Id','CVE_CVSS2_Score','CVE_CVSS2_Severity','CVE_CVSS2_Vector','CVE_CVSS3_Score','CVE_CVSS3_Severity','CVE_CVSS3_Vector']
    with open(filename, 'w') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for cve in cve_array:
            writer.writerow(cve)
    return

def read_txt(filename):
    cve_list =[]
    with open(filename, 'r') as f:
        for cve in f:
            cve = cve.strip()
            if is_valid_cve(cve):
                if cve_list.count(cve) == 0:
                    cve_list.append(cve)
    cve_list = sorted(cve_list)
    return cve_list

def is_valid_cve(cve):
    prog = re.compile('^(CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))$')
    return prog.match(cve)

def get_cve_details (cve):
    cve_obj = {
                'CVE_Id': cve, 
                'CVE_CVSS2_Score'   : '',
                'CVE_CVSS2_Severity': '',
                'CVE_CVSS2_Vector'  : '' ,
                'CVE_CVSS3_Score'   : '',
                'CVE_CVSS3_Severity': '',
                'CVE_CVSS3_Vector'  : ''
              }
    page = urllib.request.urlopen('https://nvd.nist.gov/vuln/detail/'+cve)
    page_content = page.read()
    encoding = page.headers.get_content_charset('utf-8')
    source = page_content.decode(encoding)

    # TODO look for cvss v2 and v3 hidden fields, and have different soups

    soup = BeautifulSoup(source, 'html.parser')

    data = soup.find('span', {"data-testid":"vuln-cvssv2-base-score"})
    if data:
        if data.contents:
            cve_obj['CVE_CVSS2_Score'] = data.contents[0].replace(')','').replace('(','').strip()
    
    data = soup.find('span', {"data-testid":"vuln-cvssv2-base-score-severity"})
    if data:
        if data.contents:
            cve_obj['CVE_CVSS2_Severity'] = data.contents[0].replace(')','').replace('(','').strip()

    data = soup.find('span', {"data-testid":"vuln-cvssv2-vector"})
    if data:
        if data.contents:
            cve_obj['CVE_CVSS2_Vector'] = data.contents[0].replace(')','').replace('(','').strip()

    data = soup.find('span', {"data-testid":"vuln-cvssv3-base-score"})
    if data:
        if data.contents:
            cve_obj['CVE_CVSS3_Score'] = data.contents[0].replace(')','').replace('(','').strip()
    
    data = soup.find('span', {"data-testid":"vuln-cvssv3-base-score-severity"})
    if data:
        if data.contents:
            cve_obj['CVE_CVSS3_Severity'] = data.contents[0].replace(')','').replace('(','').strip()

    data = soup.find('span', {"data-testid":"vuln-cvssv3-vector"})
    if data:
        if data.contents:
            cve_obj['CVE_CVSS3_Vector'] = data.contents[0].replace(')','').replace('(','').strip()




    if  cve_obj['CVE_CVSS2_Score'] == 10.0 or cve_obj['CVE_CVSS3_Severity'] == 'CRITICAL':
        cve_obj['CVE_CVSS2_Severity'] = 'CRITICAL'
    
    return cve_obj

def cves_thread(n, cve_list):
    global cve_obj_array
 
    #print('{}({}) => {}'.format (n,len(cve_list),cve_list))
    for cve in cve_list:
        try:
            cve_obj = get_cve_details(cve)
            if cve_obj:
                print('{} | CVSS2={}: {}: {} | CVSS3={}: {}: {}'.format(cve_obj['CVE_Id'],
                            cve_obj['CVE_CVSS2_Score'],cve_obj['CVE_CVSS2_Severity'],cve_obj['CVE_CVSS2_Vector'],
                            cve_obj['CVE_CVSS3_Score'],cve_obj['CVE_CVSS3_Severity'],cve_obj['CVE_CVSS3_Vector']))
                cve_obj_array.append(cve_obj)
        except:
            print('Error for {}'.format(cve))
    return

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--input', help='Input file')
    parser.add_argument('-o', '--output', help='Output file')
    args = parser.parse_args()
    if args.input:
        input = args.input
    if args.output:
        output = args.output

    cve_list = read_txt(input)
    length = len(cve_list)
    thread_len = int(length/thread_cnt)
    if length/thread_cnt > thread_len:
        thread_len += 1
    print ('{} CVEs = {} threads x {} CVEs'.format(length,thread_cnt, thread_len))

    threads = []
    finish = False
    for x in range(thread_cnt):
        if thread_len*x >= length:
            break
        cve_list_thread = []
        for y in range(thread_len):
            if thread_len*x +y >= length:
                thread = threading.Thread(target=cves_thread, args=(x+1,cve_list_thread,))
                threads.append(thread)
                finish = True
                break
            cve_list_thread.append(cve_list[thread_len*x +y])
        if not finish:
            thread = threading.Thread(target=cves_thread, args=(x+1,cve_list_thread,))
            threads.append(thread)
 
    # start threads
    for t in threads:
        t.start()

    # wait for the threads to finish
    for t in threads:
        t.join()

    if len(cve_obj_array) > 0:
        save_csv(cve_obj_array, output)
