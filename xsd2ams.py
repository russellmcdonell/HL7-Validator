# pylint: disable=line-too-long
'''
Script xsd2ams.py
A script to render an HL7 v2.xml XML schema as an HL7 Abstract Message Structure

This script reads an HL7 v2.x message structure from the 'xsd' schema folder
and then renders it a an HL7 Abstract Message Structure which is written to an Excel Workbook


    SYNOPSIS
    $ python bar2xml.py
        [-m messageStructure|--messageStructure=messageStructure]
        [-S schemaDir|--schemaDir=schemaDir]
        [-O outputDir|--outputDir=outputDir]
        [-o outputFile|--outputFile=outputFile]
        [-v loggingLevel|--verbose=loggingLevel]
        [-L logDir|--logDir=logDir]
        [-l logfile|--logfile=logfile]
        messageStructure ...


    REQUIRED
    -m messageStructure|--messageStructure=messageStructure
    The name of the HL7 v2.xml message structure definition file to be rendered.

    
    OPTIONS
    -S schemaDir|--schemaDir=schemaDir
    The folder containing the HL7 v2.xml XML Schema files for the relevant version of HL7 v2.x
    (default = 'schema/v2.4')

    -O outputDir|--outputDir=outputDir
    The folder where the output file of the Abstract Message Structure will be created as an Excel Workbook.

    -o outputFilename|--outputFilename=outputFilename
    The name of the Excel Workbook containing the Abstract Message Structure to be created

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
import csv
import pandas as pd
from xml.etree import ElementTree as et
from openpyxl import Workbook

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

hl7segments = {}        # The description and chapter for each segment
namespaces={'xsd':'http://www.w3.org/2001/XMLSchema'}   # The namespaces in the XSD message structure definition
messageRoot = None      # The root of the XSD message structure definition
lines = []              # The list of lines that make up this AMS


def getAppendixA():

    global hl7segments
    
    # Check that HL7 and User tables Excel Workbook exists
    if not os.path.isfile(os.path.join(schemaDir, 'Appendix A.xlsx')):
        logging.critical('No Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    hl7segments = {}
    dTypes = {'Segmemt':str, 'Description':str, 'Chapter':str}
    dfSheets = pd.read_excel(os.path.join(schemaDir, "Appendix A.xlsx"), sheet_name=None, dtype=dTypes, na_filter=False)
    if "Appendix A.4 Segments" not in dfSheets:
        logging.critical('Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd) does not have a Worksheet named "Appendix A.4 Segments"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    segmentsDf = dfSheets["Appendix A.4 Segments"]
    if "Segment" not in segmentsDf.columns.values.tolist():
        logging.critical('Missing column "Segment" in Worksheet "Appendix A.4 Segments" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "Description" not in segmentsDf.columns.values.tolist():
        logging.critical('Missing column "Description" in Worksheet "Appendix A.4 Segments" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "Chapter" not in segmentsDf.columns.values.tolist():
        logging.critical('Missing column "Chapter" in Worksheet "Appendix A.4 Segments" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    segmentsData = segmentsDf.to_dict(orient='records')
    for row in segmentsData:
        seg = row['Segment']
        description = row['Description']
        chapter = row['Chapter']
        hl7segments[seg] = (description, chapter)
    return


def render(sequence, indent, isChoice):
    '''
    Render an XML sequence as an Abstract Message Structure
    PARAMETERS:
        sequence, XML Element - an XML Schema sequence definition
    RETURNS:
        lines, list - list of lines for of the AMS
    '''

    firstSeg = True
    for segNo, seg in enumerate(sequence):
        name = seg.attrib['ref']
        if name.startswith('any'):
            continue
        if len(name) == 3:      # A segment
            if name in hl7segments:
                segName, chapter = hl7segments[name]
            else:
                segName = 'Unknown'
                chapter = ''
            if isChoice:
                if firstSeg:
                    firstSeg = False
                    name = '<' + name
                    if segNo == (len(sequence) - 1):
                        name = name + '>'
                    else:
                        name = name + '|'
                elif segNo == (len(sequence) - 1):
                    name = ' ' + name + '>'
                else:
                    name = ' ' + name + '|'
            if seg.attrib['maxOccurs'] == 'unbounded':
                name = '{' + name + '}'
            if seg.attrib['minOccurs'] == '0':
                name = '[' + name + ']'
            lines.append([indent + name, segName, chapter])
        else:
            if seg.attrib['minOccurs'] == '0':
                lines.append([indent + '[', name + ' - begin', ''])
                indent += '   '
                if seg.attrib['maxOccurs'] == 'unbounded':
                    lines.append([indent + '{', '', ''])
                    indent += '   '
            elif seg.attrib['maxOccurs'] == 'unbounded':
                lines.append([indent + '{', name + ' - begin', ''])
                indent += '   '
            thisChoice = False
            newSequence = messageRoot.find("xsd:complexType[@name='" + name + ".CONTENT']/xsd:sequence", namespaces)
            if newSequence is None:
                thisChoice = True
                newSequence = messageRoot.find("xsd:complexType[@name='" + name + ".CONTENT']/xsd:choice", namespaces)
            # logging.debug('newSequence for name(%s) - %s, isChoice(%s)', name, repr(newSequence), isChoice)
            render(newSequence, indent, thisChoice)
            if seg.attrib['minOccurs'] == '0':
                if seg.attrib['maxOccurs'] == 'unbounded':
                    indent = indent[:-3]
                    lines.append([indent + '}', '' ''])
                indent = indent[:-3]
                lines.append([indent + ']', name + ' - end', ''])
            elif seg.attrib['maxOccurs'] == 'unbounded':
                indent = indent[:-3]
                lines.append([indent + '}', name + ' - end' ''])
    return



if __name__ == '__main__':
    '''
    The main code
    Start by parsing the command line arguements and setting up logging.
    Then process the HL7 v2.xml message structure definition.
    '''

    # Set the command line options
    progName = sys.argv[0]
    progName = progName[0:-3]        # Strip off the .py ending
    parser = argparse.ArgumentParser(description='bar2xml')
    parser.add_argument('-m', '--messageStructure', required=True, dest='messageStructure',
                        help='The name of the HL7 v2.xml message structure file')
    parser.add_argument('-S', '--schemaDir', dest='schemaDir', default='schema/v2.4',
                        help='The folder containing the HL7 v2.xml XML schema files (default="schema/v2.4")')
    parser.add_argument('-O', '--outputDir', dest='outputDir', default='schema/v2.4',
                        help='The folder where Excel Workbook containing the HL7 Abstact Message Structure will be created (default="schema/v2.4")')
    parser.add_argument('-o', '--outputFile', dest='outputFile', default=None,
                        help='The filename of the Excel Workbook containing the HL7 Abstract Message Structure to be created (default="messageStructure.xlsx")')
    parser.add_argument ('-v', '--verbose', dest='verbose', type=int, choices=range(0,5),
                         help='The level of logging\n\t0=CRITICAL,1=ERROR,2=WARNING,3=INFO,4=DEBUG')
    parser.add_argument ('-L', '--logDir', dest='logDir', default='.', metavar='logDir',
                         help='The name of the directory where the logging file will be created')
    parser.add_argument ('-l', '--logFile', dest='logFile', metavar='logfile', help='The name of a logging file')
    parser.add_argument('messageStructures', nargs='*',
                        help='The basename of the HL7 v2.xml message structure file(s)')

    # Parse the command line
    args = parser.parse_args()
    msgStruct = args.messageStructure
    schemaDir = args.schemaDir
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
    logging.debug('Logging set up')
    logging.debug(msgStruct)

    # Check that the schemaDir folder exist
    if not os.path.isdir(schemaDir):
        logging.critical('No schemaDir folder named "%s"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if not os.path.isdir(os.path.join(schemaDir, 'xsd')):
        logging.critical('No schemaDir folder named "%s/xsd"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)

    # Load the Appendix A data
    getAppendixA()

    # Check that the message structure file exists and read it in
    if not os.path.isfile(os.path.join(schemaDir, 'xsd', msgStruct + '.xsd')):
        logging.critical('Unknown message structure (%s)', msgStruct)
        logging.shutdown()
        sys.exit(EX_DATAERR)
    messageTree = et.parse(os.path.join(schemaDir, 'xsd', msgStruct + '.xsd'))
    messageRoot = messageTree.getroot()
    segmentList = messageRoot.find("xsd:complexType[@name='" + msgStruct + ".CONTENT']/xsd:sequence", namespaces)

    # Create the output Excel Workbook
    if outputFile is None:
        outputFile = msgStruct + '.xlsx'
    if outputDir is not None:
        outputFile = os.path.join(outputDir, outputFile)
    wb = Workbook()

    # Process the message structure

    # Check that the definintion starts with MSH
    if segmentList[0].attrib['ref'] != 'MSH' :
        logging.critical('MSH not defined for messages structure(%s)', msgStruct)
        logging.shutdown()
        sys.exit(EX_CONFIG)

    # Now create the HL7 v2 Abstract Message Structure output
    lines = []
    lines.append([msgStruct, msgStruct, 'Chapter'])
    render(segmentList, '', False)
    msgAMS = ''
    for line in lines:
        msgAMSline = '\t'.join(line)
        msgAMS += msgAMSline + '\n'

    # Save the HL7 V2 Abstract Message Structure
    logging.info(msgAMS)
    ws = wb.active
    ws.title = msgStruct
    for line in lines:
        ws.append(line)
    wb.save(outputFile)
