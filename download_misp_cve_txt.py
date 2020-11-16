import argparse
import logging
import os
from pymisp import ExpandedPyMISP
import re
from credentials import misp_key,misp_url

output = './in/misp-cve.txt'
output = os.path.join(os.path.dirname(os.path.abspath(__file__)), output)

def write_txt(filename, cve_list):
    f = open(filename, 'w')
    for cve in cve_list:
        f.write(cve+'\n')
    f.close()

def is_valid_cve(cve):
    # ^(CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))$
    prog = re.compile('^(CVE-(1999|2\d{3})-(0\d{2}[0-9]|[1-9]\d{3,}))$')
    return prog.match(cve)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-o', '--output', help='Output csv file')
    parser.add_argument('-k', '--key', help='MISP APi key')

    args = parser.parse_args()
    if args.output:
        output = args.output
    if args.key:
        misp_key = args.key

    logger = logging.getLogger ('download_misp')
    logger.setLevel (logging.INFO) # enable debug to stdout

    if output is not None and os.path.exists(output):
        logger.error('Output file already exists, overwrite')

    cve_list = []
    pymisp = ExpandedPyMISP(misp_url, misp_key, debug=False)

    s = pymisp.search('attributes', value='CVE-%')
    if 'Attribute' not in s:
        exit()
    attributes = s.get('Attribute')

    for a in attributes:
        if a['type'] == 'vulnerability':
            cve = a['value']
            if is_valid_cve(cve):
                # print('{}'.format(cve))
                if cve_list.count(cve) == 0:
                    cve_list.append(cve)

    length = len(cve_list)
    logger.info ('{} CVEs'.format(length))
    if length:
        cve_list = sorted(cve_list)
        write_txt(output, cve_list)
