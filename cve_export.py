#
from pprint import pprint
from tenable.sc import TenableSC
import argparse
import logging
import os
import re
from credentials import sc_username,sc_password,sc_address
import getpass

# global definitions
output = './in/nist-cve.txt'
output = os.path.join(os.path.dirname(os.path.abspath(__file__)), output)

def write_txt(filename, cve_list):
  f = open(filename, 'w')
  for cve in cve_list:
    f.write(cve+'\n')
  f.close()


def is_valid_cve(cve):
  #^(CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))$
  prog = re.compile(r'^(CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))$')
  return prog.match(cve)


if __name__ == '__main__':

  parser = argparse.ArgumentParser()
  parser.add_argument('-o', '--output', help='Output CVE list file')
  parser.add_argument('-u', '--username', help='User name')
  parser.add_argument('-p', '--password', help='Prompt for user password? [yes/no]')

  args = parser.parse_args()
  if args.output:
    output = args.output
  if output is not None and os.path.exists(output):
    print(output)
    print('Output file already exists, abort')
    exit(0)

  if args.username:
    sc_username = args.username
  if args.password:
    if args.password != 'no':
      sc_password = getpass.getpass('Password:')

  sc = TenableSC(sc_address)
  sc.login(sc_username, sc_password)

  cve_list=[]
  cves = sc.analysis.vulns(tool='sumcve')
  for elem in cves:
    cve= elem['cveID']
    if is_valid_cve(cve):
      #print('{}'.format(cve))
      if cve_list.count(cve) == 0:
        cve_list.append(cve)

  length=len(cve_list)
  print ('{} CVEs'.format(length))
  if length:
    cve_list = sorted(cve_list)
    write_txt(output,cve_list)  
