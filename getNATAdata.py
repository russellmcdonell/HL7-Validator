'''
Script to get NATA Accreditation numbers and Organisation Names
from the NATA website (https://nata.com.au)
This script reads an HL7 v2.x message structure from the 'xsd' schema folder
and then renders it as a train diagram (boxes for segment, arrows for optional and repeating)
and saves that as an image file.


    SYNOPSIS
    $ python bar2xml.py
        [-m messageStructure|--messageStructure=messageStructure]
        [-S schemaDir|--schemaDir=schemaDir]
        [-O outputDir|--outputDir=outputDir]
        [-o outputFile|--outputFile=outputFile]
        [-v loggingLevel|--verbose=loggingLevel]
        [-L logDir|--logDir=logDir]
        [-l logfile|--logfile=logfile]


    REQUIRED

    OPTIONS
    -O outputDir|--outputDir=outputDir
    The folder where the NATAdata.csv file will be saved (default = schema/ADRM).

    -o outputFilename|--outputFilename=outputFilename
    The name of the CSV file of NATA data to be created (default = 'NATAdata.csv')

    -v loggingLevel|--verbose=loggingLevel
    Set the level of logging that you want.

    -L logDir|--logDir=logDir
    The directory where the log file will be created (default=".").

    -l logfile|--logfile=logfile
    The name of a log file where you want all messages captured.

'''


# pylint: disable=invalid-name, pointless-string-statement, global-statement, superfluous-parens

import os
import sys
import logging
import argparse
import re
from openpyxl import Workbook
from time import sleep
import requests
from bs4 import BeautifulSoup

# This next section is plagurised from /usr/include/sysexits.h
EX_OK = 0               # successful termination
EX_WARN = 1             # non-fatal termination with warnings

EX_USAGE = 64           # command line usage error
EX_DATAERR = 65         # data format error
EX_NOINPUT = 66         # cannot open input
EX_NOUSER = 67          # addressee unknown
EX_NOHOST = 68          # host name unknown
EX_UNAVAILABLE = 69     # service unavailable
EX_SOFTWARE = 70        # internal software error
EX_OSERR = 71           # system error (e.g., can't fork)
EX_OSFILE = 72          # critical OS file missing
EX_CANTCREAT = 73       # can't create (user) output file
EX_IOERR = 74           # input/output error
EX_TEMPFAIL = 75        # temp failure; user is invited to retry
EX_PROTOCOL = 76        # remote error in protocol
EX_NOPERM = 77          # permission denied
EX_CONFIG = 78          # configuration error


isVet = re.compile(r'Veterinary|Animal', re.IGNORECASE)  # A regex pattern to match "Pathology" or "Clinical Lab" in a case-insensitive manner
removeComment = re.compile(r'\s*\([^\)]*\).*')  # A regex pattern to remove comments enclosed in parentheses


def getNATAdata(soup, ws):
    '''
    Get the NATA Accreditation numbers and Organisation Names from the NATA website
    '''

    global labs

    anchors = soup.select('a')
    for anchor in anchors:
        href = anchor.get('href')
        if href and href.startswith('https://nata.com.au/accredited-organisation/'):
            bits = href.split('-')
            NATAnumber = bits[-2]
            siteNumber = bits[-1]
            siteNumber = siteNumber.split('/')[0].strip()
            paras = anchor.find_all('p')
            origName = paras[0].text.strip()
            orgName = paras[0].text.strip()
            if isVet.search(orgName) is not None:
                continue  # Skip if the organisation name contains "Veterinary" or "Animal"
            orgName = orgName.replace('"', '')  # Remove double quotes from the organisation name
            orgNames = orgName.split('\n')
            orgName = removeComment.sub('', orgNames[0])  # Remove comments from the organisation name
            orgName = orgName.strip()  # Remove leading and trailing whitespace from the organisation name
            if orgName.find('    ') != -1:
                orgName = orgName.split('    ')[0]
            if origName != orgName:
                logging.warning(f'Original name "{origName}" is different from cleaned organisation name "{orgName}"')
            siteName = paras[1].text.strip()
            if isVet.search(siteName) is not None:
                continue  # Skip if the site name contains "Veterinary" or "Animal"
            siteName = siteName.replace('"', '')  # Remove double quotes from the site name
            siteNames = siteName.split('\n')
            siteName = removeComment.sub('', siteNames[0])  # Remove comments from the site name
            siteName = siteName.strip()  # Remove leading and trailing whitespace from the site name
            if siteName.find('    ') != -1:
                siteName = siteName.split('    ')[0]
            if siteName.startswith('Accreditation'):
                siteName = ''  # Clear the site name if it starts with "Accreditation"
            addressTag = anchor.find('span')
            for br in addressTag.find_all('br'):
                br.replace_with(', ')  # Replace <br> tags with commas for better formatting
            address = addressTag.get_text().strip()
            address = address.replace('"', '')  # Remove double quotes from the address
            address = address.replace('\n', ', ')  # Replace newlines with commas
            address = address.replace('<br>', ', ')  # Replace <br> tags with commas
            response = requests.get(href, headers=headers)
            contactName = ''
            phoneNo = ''
            emailAddress = ''
            if response.status_code == 200:
                thisSoup = BeautifulSoup(response.content, "html.parser")
                contact = thisSoup.find('p', string=re.compile(r'Contact', re.IGNORECASE))
                if contact:
                    div = contact.find_next_sibling('div')
                    if div:
                        name = div.find('span')
                        if name:
                            contactName = name.text.strip()
                            phone = name.find_next_sibling('span')
                            if phone:
                                phoneNo = phone.text.strip()
                                if phoneNo.startswith('P:'):
                                    phoneNo = phoneNo[2:].strip()
                                email = phone.find_next_sibling('span')
                                if email:
                                    emailSpan = email.find('span')
                                    if emailSpan:
                                        name = emailSpan['data-name']
                                        domain = emailSpan['data-domain']
                                        emailAddress = f"{name[::-1]}@{domain[::-1]}"
            if orgName not in labs:
                labs[orgName] = {}
            if NATAnumber not in labs[orgName]:
                labs[orgName][NATAnumber] = {}
            if contactName not in labs[orgName][NATAnumber]:
                labs[orgName][NATAnumber][contactName]= {}
            contact = tuple([phoneNo, emailAddress])
            if contact not in labs[orgName][NATAnumber][contactName]:
                labs[orgName][NATAnumber][contactName][contact] = []
            site = tuple([siteName, siteNumber, address])
            if site not in labs[orgName][NATAnumber][contactName][contact]:
                labs[orgName][NATAnumber][contactName][contact].append(site)


headers = {
    # Emulate a modern desktop browser
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}

if __name__ == '__main__':
    '''
    The main code
    Start by parsing the command line arguements and setting up logging.
    Then process screen scrape that NATA website.
    '''

    # Set the command line options
    progName = sys.argv[0]
    progName = progName[0:-3]        # Strip off the .py ending
    parser = argparse.ArgumentParser(description='bar2xml')
    parser.add_argument('-O', '--outputDir', dest='outputDir', default='schema/ADRM',
                        help='The folder where the ".png" file will be saved [messageStructure.png] (default="schema/ADRM")')
    parser.add_argument('-o', '--outputFile', dest='outputFile', default="NATAdata.xlsx",
                        help='The filename of the NATA data file to be created (default="NATAdata.xlsx")')
    parser.add_argument ('-v', '--verbose', dest='verbose', type=int, choices=range(0,5),
                         help='The level of logging\n\t0=CRITICAL,1=ERROR,2=WARNING,3=INFO,4=info')
    parser.add_argument ('-L', '--logDir', dest='logDir', default='.', metavar='logDir',
                         help='The name of the directory where the logging file will be created')
    parser.add_argument ('-l', '--logFile', dest='logFile', metavar='logfile', help='The name of a logging file')

    # Parse the command line
    args = parser.parse_args()
    outputDir = args.outputDir
    outputFile = args.outputFile
    logDir = args.logDir
    logFile = args.logFile
    loggingLevel = args.verbose

    # Set up logging
    logging_levels = {0:logging.CRITICAL, 1:logging.ERROR, 2:logging.WARNING, 3:logging.INFO, 4:logging.DEBUG}
    logfmt = progName + ' [%(asctime)s]: %(message)s'
    if loggingLevel is not None:    # Change the logging level from "WARN" if the -v vebose option is specified
        if logFile is not None:        # and send it to a file if the -o logfile option is specified
            with open(os.path.join(logDir, logFile), 'wt', encoding='utf-8', newline='') as logOutput:
                pass
            logging.basicConfig(format=logfmt, datefmt='%d/%m/%y %H:%M:%S %p', level=logging_levels[loggingLevel], filename=os.path.join(logDir, logFile))
        else:
            logging.basicConfig(format=logfmt, datefmt='%d/%m/%y %H:%M:%S %p', level=logging_levels[loggingLevel])
    else:
        if logFile is not None:        # send the default (WARN) logging to a file if the -o logfile option is specified
            with open(os.path.join(logDir, logFile), 'wt', encoding='utf-8', newline='') as logOutput:
                pass
            logging.basicConfig(format=logfmt, datefmt='%d/%m/%y %H:%M:%S %p', filename=os.path.join(logDir, logFile))
        else:
            logging.basicConfig(format=logfmt, datefmt='%d/%m/%y %H:%M:%S %p')
    logging.info('Logging set up')

    headers = {
        # Emulate a modern desktop browser
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Open the output file for writing
    wb = Workbook()
    ws = wb.active
    ws.title = "NATA Data"
    ws.append(['Organisation Name', 'NATA Accreditation Number', 'Contact Name', 'Phone Number', 'Email Address', 'Site Name', 'Site Number', 'Site Address'])
    labs = {}

    for service in ["pathology", "cytopathology", "microbiology", "haematology", "immunohaematology", "infertility"]:
        # Get the NATA data from the NATA website
        # Make the first request
        print(f"Getting page 1 of NATA data for service: {service}")
        response = requests.get(f'https://nata.com.au/?post_type=site&s={service}&filter=service&state=&status=', headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, "html.parser")
            getNATAdata(soup, ws)

        # Make the remaining requests
        for page in range(2, 10000):
            sleep(2)  # Be nice to the NATA website and don't hammer it with requests
            print(f"Getting page {page} of NATA data for service: {service}")
            response = requests.get(f'https://nata.com.au/page/{page}/?post_type=site&s={service}&filter=service&state=&status=', headers=headers)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, "html.parser")
                getNATAdata(soup, ws)
            else:
                break

    row = [None,None,None,None,None,None,None,None]
    for lab in sorted(labs):
        row[0] = lab
        for number in sorted(labs[lab]):
            row[1] = number
            for contactName in labs[lab][number]:
                row[2] = contactName
                for contact in labs[lab][number][contactName]:
                    phoneNo, emailAddress = list(contact)
                    row[3] = phoneNo
                    row[4] = emailAddress
                    for site in labs[lab][number][contactName][contact]:
                        siteName, siteNumber, address = list(site)
                        row[5] = siteName
                        row[6] = siteNumber
                        row[7] = address
                        ws.append(row)
                        row = [None,None,None,None,None,None,None,None]
    wb.save(os.path.join(outputDir, outputFile.replace('.csv', '.xlsx')))
               