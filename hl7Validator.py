# pylint: disable=line-too-long
'''
Script hl7Validator.py
A script to validate an HL7 v2.x vertical bar message with respect to it's equivalient HL7 v2.xml XML schema.
This script also outputs the equivalent HL7 v2.xml XML tagged message.


This script reads an HL7 v2.x vertical bar message from <stdin>, or a file,
or all the message files in a folder.


    SYNOPSIS
    $ python hl7Validator.py [-I inputDir|--inputDir=inputDir]
        [-i inputFile|--inputFile=inputFile]
        [-R reportDir|--reportDir=reportDir]
        [-O outputDir|--outputDir=outputDir]
        [-S schemaDir|--schemaDir=schemaDir]
        [-v loggingLevel|--verbose=logingLevel]
        [-L logDir|--logDir=logDir]
        [-l logfile|--logfile=logfile]
        [-|filename]...


    REQUIRED


    OPTIONS
    -I inputDir|--inputDir=inputDir
    The folder containing the HL7 vertical bar message(s).

    -i inputFile|--inputFile=inputFile
    The name of the HL7 vertical bar message file to be validated.

    -R reportDir|--reportDir=reportDir
    The directory where the report file(s) will be created (default=".").

    -O outputDir|--outputDir=outputDir
    The folder where the output file(s) will be created.

    -S schemaDir|--schemaDir=schemaDir
    The folder containing the HL7 v2.xml XML Schema files for the relevant version of HL7 v2.x
    (default = 'schema/v2.4')

    -v loggingLevel|--verbose=loggingLevel
    Set the level of logging that you want.

    -L logDir|--logDir=logDir
    The directory where the log file will be created (default=".").

    -l logfile|--logfile=logfile
    The name of a log file where you want all messages captured.
'''

# pylint: disable=invalid-name, bare-except, pointless-string-statement, global-statement; superfluous-parens

import os
import sys
import logging
import argparse
import re
import copy
from openpyxl import load_workbook
import pandas as pd
from lxml import etree as et
import pyDMNrules as dmn


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

Segments = []           # The Segments in the message being converted
SegmentStatus = []      # False if the segments has been found to be unexpected
segmentNo = 0           # The next segment in the message to be converted
segmentRoot = None      # The XML Schema for the segments
fieldRoot = None        # The XML Schema for the fields
dataTypeRoot = None     # The XML Schema for the data types
messageRoot = None      # The XML Schema for the message being converted
namespaces = None       # The namespaces of the XML Schemas
fieldSep = None         # The field separator character
repSep = None           # The repeat separator
escChar = None          # The escape character
compSep = None          # The component separator
subCompSep = None       # The subcomponent separator
xmlReplacements = [
    re.compile(r'\\(H)\\'),
    re.compile(r'\\(N)\\'),
    re.compile(r'\\(\.br)\\'),
    re.compile(r'\\(\.sp\s*\d+)\\'),
    re.compile(r'\\(\.in\s*[-+]?\d+)\\'),
    re.compile(r'\\(\.ti\s*[-+]?\d+)\\')
]
charXref = re.compile(r'\\X([0-9A-Fa-f][0-9A-Fa-f])+\\')
charZref = re.compile(r'\\Z([0-9A-Fa-f][0-9A-Fa-f])+\\')
hl7charRef = re.compile(r'&amp;(#x([0-9A-Fa-f][0-9A-Fa-f])+;)')
DTpattern = re.compile(r'^[12]\d{3}((0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])?)?$')
DTMpattern = re.compile(r'^[12]\d{3}((0[1-9]|1[0-2])((0[1-9]|[12]\d|3[01])(([01]\d|2[0-4])([0-5]\d([0-5]\d(\.\d{1,4})?)?)?)?)?)?([-+]?(0\d|1[0-3])[0-5]\d)?$')
NMpattern = re.compile(r'^[-+]?\d+(\.\d*)?$')
RI2pattern = re.compile(r'^([01]\d|2[0-4])[0-5]\d(,([01]\d|2[0-4])[0-5]\d)*$')
SIpattern = re.compile(r'^\d{1,4}$')
TMpattern = re.compile(r'^([01]\d|2[0-4])([0-5]\d([0-5]\d(\.\d{1,4})?)?)?([-+]?(0\d|1[0-3])[0-5]\d)?$')
TNpattern = re.compile(r'^(\d\d)?((\d{3}))?\d{3}-\d{4}(X\d{4})?(B\d{4})?(C.*)?$')
TS2pattern = re.compile(r'^[YLDMHS]$')
Hexpattern = re.compile(r'^[A-Fa-f0-9]*$')
Base64pattern = re.compile(r'^[A-Za-z0-9+/]={0,2}$')
isSeg = re.compile(r'^[A-Z][A-Z0-9]{2}$')
msgStruct = None
reportFile = None                   # The report file
hl7messageStructures = None         # The HL7 messages structures for each trigger
hl7Tables = None                    # The HL7 and User tables
fieldLengths = None                 # The maximum length of any field
datatypeLengths = None              # The maximum length of datatype components
valueSets = None                    # The value sets for CE, CF, CNE and CWE coded elements
dataTypeBusinessRules = {}          # The business rules associated with specific datatypes
fieldBusinessRules = {}             # The business rules associated with specific fields
segmentBusinessRules = {}           # The business rules associated with specific segments
XPathBusinessRules = {}             # Whole of message business rules based upon XPath expressions
rulesEngine = None                  # The DMN rules engine for validating fields
glossary = {}                       # The glossary from the Rules Engine
XMLclean = re.compile(u'[^\u0020-\uD7FF\u0009\u000A\u000D\uE000-\uFFFD\U00010000-\U0010FFFF]+')


def getAppendixA(schemaDir):
    # Check that HL7 and User tables Excel Workbook exists

    global hl7messageStructures, hl7Tables, fieldLengths

    if not os.path.isfile(os.path.join(schemaDir, 'Appendix A.xlsx')):
        logger.critical('No Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    hl7messageStructures = {}
    hl7Tables = {}
    dTypes = {'Type':str, 'Table':str, 'Value':str, 'Description':str, 'Seg':str, 'Seq#':str, 'Len':str}
    dfSheets = pd.read_excel(os.path.join(schemaDir, "Appendix A.xlsx"), sheet_name=None, dtype=dTypes, na_filter=False)
    if "Appendix A.6 Tables Numeric" not in dfSheets:
        logger.critical('Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd) does not have a Worksheet named "Appendx A.6 Tables Numeric"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    tablesDf = dfSheets["Appendix A.6 Tables Numeric"]
    tablesDf['Table'] = tablesDf['Table'].str.zfill(4)
    tablesDf.loc[tablesDf['Table'].eq("0000"), 'Table'] = ''
    if "Type" not in tablesDf.columns.values.tolist():
        logger.critical('Missing column "Type" in Worksheet "Appendx A.6 Tables Numeric" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "Table" not in tablesDf.columns.values.tolist():
        logger.critical('Missing column "Table" in Worksheet "Appendx A.6 Tables Numeric" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "Value" not in tablesDf.columns.values.tolist():
        logger.critical('Missing column "Value" in Worksheet "Appendx A.6 Tables Numeric" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "Description" not in tablesDf.columns.values.tolist():
        logger.critical('Missing column "Description" in Worksheet "Appendx A.6 Tables Numeric" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    tablesData = tablesDf.to_dict(orient='records')
    tableType = None
    tableNumber = None
    tableCode = None
    for row in tablesData:
        if row['Type'] != '':
            tableType = row['Type']
        if row['Table'] == '':
            continue                    # A "Type" only row
        if row['Table'] != tableNumber:
            tableNumber = row['Table']
            if tableType is None:
                logger.critical('Error in Worksheet "Appendx A.6 Tables Numeric" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd) - table [%s] without table type', schemaDir, tableNumber)
                logging.shutdown()
                sys.exit(EX_CONFIG)
            tableCode = f'HL7{tableNumber:04}'
            if tableCode not in hl7Tables:
                hl7Tables[tableCode] = {}
                hl7Tables[tableCode]['type']= tableType
                hl7Tables[tableCode]['codes'] = []
        tableValue = row['Value'].strip()
        if tableValue == '':
            continue
        hl7Tables[tableCode]['codes'].append(tableValue)
        if tableNumber == '0354':
            msgStructure = tableValue
            msgStruct = msgStructure[0:3]
            if msgStruct not in hl7messageStructures:
                hl7messageStructures[msgStruct] = {}
            msgTriggers = row['Description'].split(',')
            for trigger in msgTriggers:
                thisTrigger = trigger.strip()
                if len(thisTrigger) == 3:
                    hl7messageStructures[msgStruct][thisTrigger] = msgStructure
                elif (len(thisTrigger) == 7) and (thisTrigger[3:4] == '-'):
                    thisLetter = thisTrigger[0:1]
                    thisStart = int(thisTrigger[1:3])
                    thisEnd = int(thisTrigger[5:7]) + 1
                    for eachTrigger in range(thisStart, thisEnd):
                        oneTrigger = f'{thisLetter}{eachTrigger:02d}'
                        hl7messageStructures[msgStruct][oneTrigger] = msgStructure

    # Check if field length Worksheet exits
    if "Appendix A.7 Data Element Names" in dfSheets:
        fieldLengths = {}
        lengthsDf = dfSheets["Appendix A.7 Data Element Names"]
        if "Seg" not in lengthsDf.columns.values.tolist():
            logger.critical('Missing column "Seg" in Worksheet "Appendx A.7 Data Element Names" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "Seq#" not in lengthsDf.columns.values.tolist():
            logger.critical('Missing column "Seq#" in Worksheet "Appendx A.7 Data Element Names" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "Len" not in lengthsDf.columns.values.tolist():
            logger.critical('Missing column "Len" in Worksheet "Appendx A.7 Data Element Names" in Excel Workbook "Appendix A.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        lengthsData = lengthsDf.to_dict(orient='records')
        for row in lengthsData:
            seg = row['Seg']
            field = row['Seq#']
            try:
                length = int(row['Len'])
            except:
                length = 65536
            fieldCode = seg + '-' + field
            fieldLengths[fieldCode] = length
    return


def getDatatypes(schemaDir):
    # Check if the datatype Excel Workbook exists

    global datatypeLengths

    if os.path.isfile(os.path.join(schemaDir, 'data types.xlsx')):
        datatypeLengths = {}
        dTypes = {'data type':str, 'SEQ':str, 'LEN':str}
        dfDatatypes = pd.read_excel(os.path.join(schemaDir, 'data types.xlsx'), dtype=dTypes, na_filter=False)
        if "data type" not in dfDatatypes.columns.values.tolist():
            logger.critical('Missing column "data type" in in Excel Workbook "data types.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "SEQ" not in dfDatatypes.columns.values.tolist():
            logger.critical('Missing column "SEQ" in Excel Workbook "data types.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "LEN" not in dfDatatypes.columns.values.tolist():
            logger.critical('Missing column "LEN" in  Excel Workbook "data types.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        datatypes = dfDatatypes.to_dict(orient='records')
        for row in datatypes:
            dataType = row['data type']
            if dataType not in datatypeLengths:
                datatypeLengths[dataType] = {}
            try:
                seq = int(row['SEQ']) - 1
            except:
                seq = 1
            try:
                length = int(row['LEN'])
            except:
                length = 65536
            datatypeLengths[dataType][seq] = length
    return


def getValueSets(schemaDir):
    # Check if we have a ValueSets file - an Excel Workbook of value sets to be checked
    #Each field/component can have multiple value sets, each associated with a list of segment groups.

    global valueSets

    if os.path.isfile(os.path.join(schemaDir, 'value sets.xlsx')):
        valueSets = {}
        dTypes = {'group(s)':str, 'field/component':str, 'system':str, 'code':str, 'description':str}
        dfValueSets = pd.read_excel(os.path.join(schemaDir, 'value sets.xlsx'), dtype=dTypes, na_filter=False)
        if "group(s)" not in dfValueSets.columns.values.tolist():
            logger.critical('Missing column "group(s)" in in Excel Workbook "value sets.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "field/component" not in dfValueSets.columns.values.tolist():
            logger.critical('Missing column "field/component" in Excel Workbook "value sets.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "system" not in dfValueSets.columns.values.tolist():
            logger.critical('Missing column "system" in  Excel Workbook "value sets.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "code" not in dfValueSets.columns.values.tolist():
            logger.critical('Missing column "code" in  Excel Workbook "value sets.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if "description" not in dfValueSets.columns.values.tolist():
            logger.critical('Missing column "description" in  Excel Workbook "value sets.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        valueSetsData = dfValueSets.to_dict(orient='records')
        for row in valueSetsData:
            groups = row['group(s)']
            fieldComponent = row['field/component']
            system = row['system']
            code = row['code']
            description = row['description']
            if fieldComponent not in valueSets:
                valueSets[fieldComponent] = {}
            if (groups is None) or (groups.strip() == ''):
                groupList = [None]
            else:
                groupList = groups.split(',')
                for iGroup in range(len(groupList) - 1, -1, -1):
                    if groupList[iGroup].strip() == '':
                        del groupList[iGroup]
                if len(groupList) == 0:
                    groupList = [None]
            if system not in valueSets[fieldComponent]:
                valueSets[fieldComponent][system] = {}
            for group in groupList:
                if group not in valueSets[fieldComponent][system]:
                    valueSets[fieldComponent][system][group] = {}
                if code in valueSets[fieldComponent][system][group]:
                    logger.critical('Redefinition of "code" (%s) for "system" (%s) for "group" (%s) in  Excel Workbook "value sets.xlsx" in schemaDir folder(%s/xsd)', code, system, group, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
                if (description is not None) and (description.strip() != ''):
                    valueSets[fieldComponent][system][group][code] = description.split('|')
                else:
                    valueSets[fieldComponent][system][group][code] = None
    return


def getBusinessRules(schemaDir):
    '''
    Get the business rules from 'Business Rules.xlsx' and 'Business Rules DMN.xlsx' in the schemaDir folder
    '''

    global dataTypeBusinessRules, fieldBusinessRules, segmentBusinessRules, XPathBusinessRules, rulesEngine, glossary

    # Check if we have some BusinessRules files - Excel Workbooks of business rules to be tested
    dataTypeBusinessRules = {}
    fieldBusinessRules = {}
    segmentBusinessRules = {}
    XPathBusinessRules = {}
    if not os.path.isfile(os.path.join(schemaDir, 'Business Rules.xlsx')):
        return
    
    # Load the Business Rules Excel Workbook
    wb = load_workbook(os.path.join(schemaDir, 'Business Rules.xlsx'), read_only=True, data_only=True)
    if "datatype rules" not in wb.sheetnames:
        logger.critical('Missing Worksheet "datatype rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    ws = wb["datatype rules"]
    # Extract the data from the Worksheet and check that it has the required columns
    data = list(ws.iter_rows(values_only=True))
    columns = data[0] if data else []
    data_rows = data[1:] if len(data) > 1 else []
    if "datatype" != columns[0]:
        logger.critical('Missing column "datatype" in Worksheet "datatype rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "group(s)" != columns[1]:
        logger.critical('Missing column "group(s)" in Worksheet "datatype rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "segment(s)" != columns[2]:
        logger.critical('Missing column "segment(s)" in Worksheet "datatype rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "rule" != columns[3]:
        logger.critical('Missing column "rule" in Worksheet "datatype rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    for row in data_rows:
        dataType, group, segment, rule = row[0:4]
        if (dataType is None) or (str(dataType).strip() == ''):
            break
        dataType = str(dataType).strip()
        if group is None:
            groupList = [None]
        else:
            groupList = group.split(',')
            for iGroup in range(len(groupList) - 1, -1, -1):
                if groupList[iGroup].strip() == '':
                    del groupList[iGroup]
                else:
                    groupList[iGroup] = groupList[iGroup].strip()
            if len(groupList) == 0:
                groupList = [None]
        if segment is None:
            segmentList = [None]
        else:
            segmentList = segment.split(',')
            for iSegment in range(len(segmentList) - 1, -1, -1):
                if segmentList[iSegment].strip() == '':
                    del segmentList[iSegment]
                else:
                    segmentList[iSegment] = segmentList[iSegment].strip()
            if len(segmentList) == 0:
                segmentList = [None]
        if dataType not in dataTypeBusinessRules:
            dataTypeBusinessRules[dataType] = {}
        for group in groupList:
            if group not in dataTypeBusinessRules[dataType]:
                dataTypeBusinessRules[dataType][group] = {}
            for segment in segmentList:
                if segment not in dataTypeBusinessRules[dataType][group]:
                    dataTypeBusinessRules[dataType][group][segment] = []
                if rule in dataTypeBusinessRules[dataType][group][segment]:
                    continue
                dataTypeBusinessRules[dataType][group][segment].append(rule)
    if "field rules" not in wb.sheetnames:
        logger.critical('Missing Worksheet "fields rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    ws = wb["field rules"]
    # Extract the data from the Worksheet and check that it has the required columns
    data = list(ws.iter_rows(values_only=True))
    columns = data[0] if data else []
    data_rows = data[1:] if len(data) > 1 else []
    if "field(s)" != columns[0]:
        logger.critical('Missing column "field" in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "group(s)" != columns[1]:
        logger.critical('Missing column "group(s)" in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "rule" != columns[2]:
        logger.critical('Missing column "rule" in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "type" != columns[3]:
        logger.critical('Missing column "type" in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "count" != columns[4]:
        logger.critical('Missing column "count" in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    for row in data_rows:
        field, group, rule, thisType, count = row[0:5]
        if field is None:
            fieldList = [None]
        else:
            fieldList = field.split(',')
            for iField in range(len(fieldList) - 1, -1, -1):
                if fieldList[iField].strip() == '':
                    del fieldList[iField]
                else:
                    fieldList[iField] = fieldList[iField].strip()
                if not isSeg.match(fieldList[iField][0:3]):
                    logger.critical('Invalid segment code (%s)/field(%s) in column "field" in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', fieldList[iField][0:3], fieldList[iField], schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
            if len(fieldList) == 0:
                fieldList = [None]
        if group is None:
            groupList = [None]
        else:
            groupList = group.split(',')
            for iGroup in range(len(groupList) - 1, -1, -1):
                if groupList[iGroup].strip() == '':
                    del groupList[iGroup]
                else:
                    groupList[iGroup] = groupList[iGroup].strip()
            if len(groupList) == 0:
                groupList = [None]
        if thisType not in ["min", "max", "all"]:
            logger.critical('Invalid value in column "type" for field("%s"), rule("%s") of type("%s") in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', field, rule, thisType, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if thisType in ["min", "max"]:
            try:
                count = int(count)
            except:
                    logger.critical('Invalid value in column "count" for field("%s"), rule("%s") of type("%s") in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', field, rule, thisType, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
        else:
            count = None
        for field in fieldList:
            if field not in fieldBusinessRules:
                fieldBusinessRules[field] = {}
            for group in groupList:
                if group not in fieldBusinessRules[field]:
                    fieldBusinessRules[field][group] = {}
                if rule not in fieldBusinessRules[field][group]:
                    fieldBusinessRules[field][group][rule] = {}
                if thisType in fieldBusinessRules[field][group][rule]:
                    logger.critical('Duplicate rule("%s") for field("%s") of type("%s") in Worksheet "field rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, field, thisType, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
                fieldBusinessRules[field][group][rule][thisType] = count

    # Look for Segment Business Rules
    if "segment rules" not in wb.sheetnames:
        logger.critical('Missing Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    ws = wb["segment rules"]
    # Extract the data from the Worksheet and check that it has the required columns
    data = list(ws.iter_rows(values_only=True))
    columns = data[0] if data else []
    data_rows = data[1:] if len(data) > 1 else []
    if "segment" != columns[0]:
        logger.critical('Missing column "segment" in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "group(s)" != columns[1]:
        logger.critical('Missing column "group(s)" in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "rule" != columns[2]:
        logger.critical('Missing column "rule" in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "repFields" != columns[3]:
        logger.critical('Missing column "repFields " in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "type" != columns[4]:
        logger.critical('Missing column "type" in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "count" != columns[5]:
        logger.critical('Missing column "count" in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    for row in data_rows:
        segment, groups, rule, repFields, thisType, count = row[0:6]
        if (segment is None) or (str(segment).strip() == ''):
            break
        segment = str(segment).strip()
        if not isSeg.match(segment):
            logger.critical('Invalid value (%s) in column "segment" in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', segment, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if (groups is None) or (str(groups).strip() == ''):
            groupList = [None]
        else:
            groupList = groups.split(',')
            for iGroup in range(len(groupList) - 1, -1, -1):
                if groupList[iGroup].strip() == '':
                    del groupList[iGroup]
                else:
                    groupList[iGroup] = groupList[iGroup].strip()
            if len(groupList) == 0:
                groupList = [None]
        if (repFields is None) or (str(repFields).strip() == ''):
            repFields = tuple([None])
        else:
            repFieldsList = repFields.split(',')
            for iField in range(len(repFieldsList) - 1, -1, -1):
                if str(repFieldsList[iField]).strip() == '':
                    del repFieldsList[iField]
                else:
                    repFieldsList[iField] = str(repFieldsList[iField]).strip()
                    if repFieldsList[iField][0:3] != segment:
                        logger.critical('Invalid value (%s) in column "repFields" for segment(%s) in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', repFieldsList[iField], segment, schemaDir)
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
            if len(repFieldsList) == 0:
                repFields = tuple([None])
            else:
                repFields = tuple(repFieldsList)
        if (thisType is None) or (str(thisType).strip() == ''):
            thisType = None
        elif str(thisType).strip() not in ["min", "max"]:
            logger.critical('Invalid value (%s) in column "type" for field("%s"), rule("%s") of type("%s") in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', thisType, field, rule, thisType, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        else:
            thisType = str(thisType).strip()
        if thisType in ["min", "max"]:
            try:
                count = int(count)
            except:
                    logger.critical('Invalid value (%s) in column "count" for field("%s"), rule("%s") of type("%s") in Worksheet "segment rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', count, field, rule, thisType, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
        else:
            count = None
        if segment not in segmentBusinessRules:
            segmentBusinessRules[segment] = {}
        for group in groupList:
            if group not in segmentBusinessRules[segment]:
                segmentBusinessRules[segment][group] = {}
            if rule not in segmentBusinessRules[segment][group]:
                segmentBusinessRules[segment][group][rule] = {}
            if repFields not in segmentBusinessRules[segment][group][rule]:
                segmentBusinessRules[segment][group][rule][repFields] = {}
            if thisType not in segmentBusinessRules[segment][group][rule][repFields]:
                segmentBusinessRules[segment][group][rule][repFields][thisType] = {"count": count, "passed": 0}

    # Look for Message XPath Business Rules
    if "XPath rules" not in wb.sheetnames:
        logger.critical('Missing Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    ws = wb["XPath rules"]
    # Extract the data from the Worksheet and check that it has the required columns
    data = list(ws.iter_rows(values_only=True))
    columns = data[0] if data else []
    data_rows = data[1:] if len(data) > 1 else []
    if "rule" != columns[0]:
        logger.critical('Missing column "rule" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "rule path" != columns[1]:
        logger.critical('Missing column "rule path" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "rule type" != columns[2]:
        logger.critical('Missing column "rule type" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "rule count" != columns[3]:
        logger.critical('Missing column "rule count" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "field path" != columns[4]:
        logger.critical('Missing column "field path" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "field type" != columns[5]:
        logger.critical('Missing column "field type" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "field count" != columns[6]:
        logger.critical('Missing column "field count" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if "linked" != columns[7]:
        logger.critical('Missing column "linked" in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    maxXPath = 8
    while maxXPath < len(columns):
        if columns[maxXPath] != 'xpath':
            break
        maxXPath += 1
    for row in data_rows:
        rule, rulePath, ruleType, ruleCount, fieldPath, fieldType, fieldCount, linked = row[0:8]
        if (rule is None) or (str(rule).strip() == ''):
            break
        rule = str(rule).strip()
        rulePath = str(rulePath).strip()
        if not rulePath.startswith('/'):
            logger.critical('Invalid value in column "rule path" for rule("%s") of rule type("%s") in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, ruleType, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if (ruleType is not None) and (str(ruleType).strip() == ''):
            ruleType = None
        if ruleType not in ["min", "max", None]:
            logger.critical('Invalid value in column "rule type" for rule("%s") of rule type("%s") in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, ruleType, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if ruleType in ["min", "max"]:
            try:
                ruleCount = int(ruleCount)
            except:
                    logger.critical('Invalid value in column "rule count" for rule("%s") of rule type("%s") in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, ruleType, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
        else:
            ruleType = None
        if (fieldPath is None) or (str(fieldPath).strip() == ''):
            logger.critical('Missing value in column "field path" for rule("%s") of rule type("%s") in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, ruleType, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        fieldPath = str(fieldPath).strip()
        if (fieldType is not None) and str(fieldType).strip() == '':
            fieldType = None
        if fieldType not in ["min", "max", None]:
            logger.critical('Invalid value in column "field type" rule("%s") of field type("%s") in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, fieldType, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if fieldType in ["min", "max"]:
            try:
                fieldCount = int(fieldCount)
            except:
                    logger.critical('Invalid value in column "field count" for rule("%s") of field type("%s") in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, fieldType, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
        linked = str(linked).strip()
        if linked.upper() == 'Y':
            linked = True
        else:
            linked = False
        if rule not in XPathBusinessRules:
            XPathBusinessRules[rule] = {}
        if rulePath not in XPathBusinessRules[rule]:
            XPathBusinessRules[rule][rulePath] = {}
        if ruleType not in XPathBusinessRules[rule][rulePath]:
            XPathBusinessRules[rule][rulePath][ruleType] = {}
        XPathBusinessRules[rule][rulePath][ruleType]['ruleCount'] = ruleCount
        XPathBusinessRules[rule][rulePath][ruleType]['fields'] = {}
        if fieldPath not in XPathBusinessRules[rule][rulePath][ruleType]['fields']:
            XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath] = {}
        if fieldType not in XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath]:
            XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType] = {}
        if linked not in XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType]:
            XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType][linked] = {}
        else:
            logger.critical('Duplicate rule("%s") for rule path("%s")/ field path("%s") [duplicate "linked"] in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, rulePath, fieldPath, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType][linked]['fieldCount'] = fieldCount
        XPaths = []
        for col in range(8, maxXPath + 1):
            xpath = row[col]
            if (xpath is None) or (str(xpath).strip() == ''):
                break
            XPaths.append(str(xpath).strip())
        XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType][linked]['XPaths'] = XPaths
        if len(XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType][linked]['XPaths']) > 26:
            logger.critical('Too many XPaths for rule("%s") in Worksheet "XPath rules" in Excel Workbook "Business Rules.xlsx" in schemaDir folder(%s/xsd)', rule, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)

    # Read in the DMN rules
    if not os.path.isfile(os.path.join(schemaDir, 'Business Rules DMN.xlsx')):
        logger.critical('Business Rules is missing  Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    rulesEngine = dmn.DMN()
    status = rulesEngine.load(os.path.join(schemaDir, 'Business Rules DMN.xlsx'))
    if 'errors' in status:
        logger.critical('Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s) has errors (%s)', schemaDir, status['errors'])
        sys.exit(0)
    glossary = rulesEngine.getGlossary()
    # Check that there is a definition for 'Rule' in the glossary
    RuleIs = None
    RepeatNumberIs = None
    for concept in glossary:
        if 'Rule' in glossary[concept]:
            RuleIs = list(glossary[concept]['Rule'])[0]
        if 'Repeat Number' in glossary[concept]:
            RepeatNumberIs = list(glossary[concept]['Repeat Number'])[0]
    if RuleIs is None:
        logger.critical('Missing definition for "Rule" in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if RepeatNumberIs is None:
        logger.critical('Missing definition for "Repeat Number" in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    # Check that all the rules in the Business Rules.xlsx file have a corresponding decision in the Business Rules DMN.xlsx file
    decisions = rulesEngine.getDecision()
    if "Rule" not in decisions[0]:
        logger.critical('Missing column "Rule" in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    ruleColumn = decisions[0].index("Rule")
    for dataType in dataTypeBusinessRules:
        if dataType not in glossary:
            logger.critical('Missing definition for datatype Business Concept ("%s") in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', dataType, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        for group in dataTypeBusinessRules[dataType]:
            for segment in dataTypeBusinessRules[dataType][group]:
                for rule in dataTypeBusinessRules[dataType][group][segment]:
                    if f'{RuleIs} = "{rule}"' not in [row[ruleColumn] for row in decisions[1:]]:
                        logger.critical('Missing a Decision for rule("%s") for datatype("%s") in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', rule, dataType, schemaDir)
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
    for field in fieldBusinessRules:
        if field[0:3] not in glossary:
            logger.critical('Missing definition for segment Business Concept ("%s") for field("%s") in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', field[0:3], field, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        for group in fieldBusinessRules[field]:
            for rule in fieldBusinessRules[field][group]:
                if f'{RuleIs} = "{rule}"' not in [row[ruleColumn] for row in decisions[1:]]:
                    logger.critical('Missing a Decision for rule("%s") for field("%s") in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', rule, field, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
    for segment in segmentBusinessRules:
        if segment not in glossary:
            logger.critical('Missing definition for segment Business Concept ("%s") in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', segment, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        for group in segmentBusinessRules[segment]:
            for rule in segmentBusinessRules[segment][group]:
                if f'{RuleIs} = "{rule}"' not in [row[ruleColumn] for row in decisions[1:]]:
                    logger.critical('Missing a Decision for rule("%s") for segment("%s") in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', rule, segment, schemaDir)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
    for rule in XPathBusinessRules:
        if f'{RuleIs} = "{rule}"' not in [row[ruleColumn] for row in decisions[1:]]:
            logger.critical('Missing a Decision for rule("%s") for field path("%s") in Excel Workbook "Business Rules DMN.xlsx" in schemaDir folder(%s/xsd)', rule, fieldPath, schemaDir)
            logging.shutdown()
            sys.exit(EX_CONFIG)
    return


def getFieldData(data, fieldNode, xpaths, linked, repNo, rule, rulePath, ruleType):
    '''
    Get the field data from a field node and the xpath data from xpath nodes
    '''

    global reportFile, hl7XML

    fieldName = fieldNode.tag.replace(".", "-", 1)
    if len(fieldNode) == 0:
        data[fieldName] = fieldNode.text
    else:
        for componentNode in fieldNode:
            if componentNode.tag is et.Comment:
                continue
            componentNameParts = componentNode.tag.split(".")
            componentNum = componentNameParts[1]
            if len(componentNode) == 0:
                data[fieldName + "." + componentNum] = componentNode.text
            else:
                for subComponentNode in componentNode:
                    if subComponentNode.tag is et.Comment:
                        continue
                    subComponentNameParts = subComponentNode.tag.split(".")
                    subComponentNum = subComponentNameParts[1]
                    data[fieldName + "." + componentNum + "." + subComponentNum] = subComponentNode.text
    for prefixNo, xpath in enumerate(xpaths):
        if (xpath is None) or (str(xpath).strip() == ''):
            return data
        prefix = chr(ord('a') + prefixNo)
        xpath = str(xpath).strip()
        try:
            xpathNodes = fieldNode.xpath(xpath)
        except Exception as e:
            comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}:fieldPath {fieldPath}:XPath {xpath}) Testing failure - {e}'
            print(comment, file=reportFile)
            hl7XML.append(et.Comment(comment))
            continue
        if len(xpathNodes) == 0:
            continue
        for xpathNo, xpathNode in enumerate(xpathNodes):
            if xpathNode.tag is et.Comment:
                continue
            if (linked == "Y") and (xpathNo != repNo):
                continue
            parent = fieldNode.getparent()
            if (parent is None) or (len(parent.tag) != 3) or (not xpathNode.tag.startswith(parent.tag)):        # xpathNode should be a field
                comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}:fieldPath {fieldPath}:XPath {xpath}) Testing failure - xpath must return a field'
                print(comment, file=reportFile)
                hl7XML.append(et.Comment(comment))
                continue
            xpathName = prefix + xpathNode.tag.replace(".", "-", 1)
            if len(xpathNode) == 0:
                if (linked):
                    data[xpathName] = xpathNode.text
                else:
                    if xpathName not in data:
                        data[xpathName] = []
                    data[xpathName].append(xpathNode.text)
            else:
                for componentNode in xpathNode:
                    if componentNode.tag is et.Comment:
                        continue
                    componentNameParts = componentNode.tag.split(".")
                    componentNum = componentNameParts[1]
                    if len(componentNode) == 0:
                        if (linked):
                            data[xpathName + "." + componentNum] = componentNode.text
                        else:
                            if xpathName + "." + componentNum not in data:
                                data[xpathName + "." + componentNum] = []
                            data[xpathName + "." + componentNum].append(componentNode.text)
                    else:
                        for subComponentNode in componentNode:
                            if subComponentNode.tag is et.Comment:
                                continue
                            subComponentNameParts = subComponentNode.tag.split(".")
                            subComponentNum = subComponentNameParts[1]
                            if (linked):
                                data[xpathName + "." + componentNum + "." + subComponentNum] = subComponentNode.text
                            else:
                                if xpathName + "." + componentNum + "." + subComponentNum not in data:
                                    data[xpathName + "." + componentNum + "." + subComponentNum] = []
                                data[xpathName + "." + componentNum + "." + subComponentNum].append(subComponentNode.text)
    return data


def getDocument(fileName):
    '''
    Get an HL7 vertical bar message from a file or standard input
    '''
    thisHL7message = ''
    if fileName == '-':     # Use standard input
        for line in sys.stdin:
            thisHL7message += line.rstrip() + '\n'
        return thisHL7message
    if not os.path.isfile(fileName):
        logger.fatal('No file named %s', fileName)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    with open(fileName, 'rt', encoding='utf-8') as fpin:
        for line in fpin:
            thisHL7message += line.rstrip() + '\r'
        return thisHL7message


def validateXML(sequenceList, tag, previousTags, optional, isChoice, depth):
    '''
    Output an XML structure for all the elements in the sequence list where we have a matching segment in the Segments.
    If there is no matching segment then report a validation error and output the segment as an XML comment.
    PARAMETERS:
        sequenceList - et.Element, the XML sequence we are working on, from the message structure XSD
        tag - str, the group tag, if any
        previousTags - list of str, the tags of the previous groups, if any
        optional - boolean whether 'nothing found' is valid
        isChoice - boolean whether this is a choice group
        depth - int, the recursion depth
    RETURNS:
        restart - True if an unexpected segment has been found
        An XML structure
    This is a recursive routine, so we use depth to prevent indifinite recurrsion
    '''

    global segmentNo, Segments, fieldBusinessRules, segmentBusinessRules, reportFile, messageRoot, namespaces
    
    logger.info(f'validateXML(sequenceList:{len(sequenceList)},tag:{tag},previousTags:{previousTags},optional:{optional},isChoice:{isChoice},depth:{depth})', extra={'raw_message':True})
    if depth > 200:
        # Treat this segment as unexpected
        SegmentStatus[segmentNo] = False
        comment= f'Unexpected Segment, segment {segmentNo + 1:d} - "{Segments[segmentNo]}"'
        print(comment, file=reportFile)
        newElement = et.Element(tag)
        newElement.append(et.Comment(comment))
        segmentNo += 1
        return True, newElement
    restart = False     # Set to True the first time we find an unexpected segment. This will cause the calling routine to return and restart the validation from the top of the message structure
    depth += 1          # Increase the recursion depth
    sequenceAt = 0      # The index of the next definition in the sequenceList
    thisElement = None  # The XML element we are building for this group
    tagged = False      # Whether we have created the XML element for this group yet
    occurs = 0          # The number of times we have found this segment
    lastSeg = None      # The last segment we found - used to count the number of times we have found this segment
    groupOccurs = 0     # The number of times we have found this group
    lastGroup = None    # The last group we found - used to count the number of times we have found this group
    while sequenceAt < len(sequenceList):           # Check the next segment
        if not SegmentStatus[segmentNo]:            # Previously found to be an unexpected segment - report it and skip it
            comment= f'Unexpected Segment, segment {segmentNo + 1:d}: "{Segments[segmentNo]}"'
            print(comment, file=reportFile)
            if not tagged:
                thisElement = et.Element(tag)
                tagged = True
            thisElement.append(et.Comment(comment))
            segmentNo += 1
            if segmentNo < len(Segments):
                logger.debug(f'More segments after unexpected segment - continuing', extra={'raw_message':True})
                continue
            return restart, thisElement
        if 'ref' not in sequenceList[sequenceAt].attrib:
            logger.critical('XML Schema definition is missing "ref" for segment at %d in message struct %s', sequenceAt, msgStruct)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        # The next test checks if the current Segment DOES NOT match the next definition
        # There are a couple of reasons why this may be so.
        # The next definition may define a group and the current Segment should be in that group (recursion)
        # Or the next definition may define an optional segment. In which case we move past it and check the following definition.
        if sequenceList[sequenceAt].attrib['ref'] != Segments[segmentNo][0:3]:
            # Not the segment we are looking for - see if this is a group definition [references with a name more than 3 characters long]
            logger.info(f'Node:{sequenceList[sequenceAt].attrib['ref']} is not segment {Segments[segmentNo][0:3]}', extra={'raw_message':True})
            if len(sequenceList[sequenceAt].attrib['ref']) > 3:     # A group
                groupRef = sequenceList[sequenceAt].attrib['ref']
                # Check if this is the first time we have found this group. If so, reset the groupOccurs counter
                if (lastGroup is None) or (lastGroup != groupRef):
                    lastGroup = groupRef
                    groupOccurs = 0
                groupOptional = False
                if 'minOccurs' not in sequenceList[sequenceAt].attrib:
                    logger.critical('XML Schema definition is missing "minOccurs" at %d in message struct %s', sequenceAt, msgStruct)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
                if sequenceList[sequenceAt].attrib['minOccurs'] == '0':
                    groupOptional = True
                # See if this group is defined as a sequence or a choice. If neither, then this is an error in the schema
                thisChoice = False
                groupList = messageRoot.find("xsd:complexType[@name='" + groupRef + ".CONTENT']/xsd:sequence", namespaces)
                if groupList is None:
                    groupList = messageRoot.find("xsd:complexType[@name='" + groupRef + ".CONTENT']/xsd:choice", namespaces)
                    thisChoice = True
                    if groupList is None:
                        logger.critical('XML Schema definition missing either xsd:sequence or xsd:choice for %s', groupRef + '.CONTENT')
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                # Check this group using this routine (recursion)
                for thisSeg in segmentBusinessRules:
                    if tag not in segmentBusinessRules[thisSeg]:
                        continue
                    for rule in segmentBusinessRules[thisSeg][tag]:
                        for repFields in segmentBusinessRules[thisSeg][tag][rule]:
                            for thisType in segmentBusinessRules[thisSeg][tag][rule][repFields]:
                                if thisType not in ["min", "max"]:
                                    continue
                                segmentBusinessRules[thisSeg][tag][rule][repFields][thisType]['passed'] = 0
                previousTags.append(tag)
                restart, groupXML = validateXML(groupList, groupRef, previousTags, groupOptional, thisChoice, depth)           # Validate this group of segments
                if restart:     # We found an unexpected segment in this group - return to the calling routine to restart validation from the top of the message structure
                    return restart, groupXML
                if groupXML is not None:        # At least one segment was found in this group
                    logger.info(f'returned value ({groupXML.tag})', extra={'raw_message':True})
                    if not tagged:
                        thisElement = et.Element(tag)
                        tagged = True
                    thisElement.append(groupXML)
                    # Check any segment business rules for this group and report any failures
                    for thisSeg in segmentBusinessRules:
                        if tag not in segmentBusinessRules[thisSeg]:
                            continue
                        for rule in segmentBusinessRules[thisSeg][tag]:
                            for repFields in segmentBusinessRules[thisSeg][tag][rule]:
                                for thisType in segmentBusinessRules[thisSeg][tag][rule][repFields]:
                                    if thisType not in ["min", "max"]:
                                        continue
                                    passed = segmentBusinessRules[thisSeg][tag][rule][repFields][thisType]['passed']
                                    count = segmentBusinessRules[thisSeg][tag][rule][repFields][thisType]['count']
                                    if ((thisType == "min") and (passed < count)) or ((thisType == "max") and (passed > count)):
                                        comment = f'Failed Segment Business Rule ({thisSeg}:{tag}:{rule}:{repFields}:{thisType}:{count} - passed {passed})'
                                        print(comment, file=reportFile)
                                        thisElement.append(et.Comment(comment))
                    if segmentNo == len(Segments):      # Group used all the segments
                        logger.debug(f'validateXML from tag({tag}):return - no more segments', extra={'raw_message':True})
                        return restart, thisElement
                    groupOccurs += 1
                    if 'maxOccurs' not in sequenceList[sequenceAt].attrib:
                        logger.critical('XML Schema definition is missing "maxOccurs" at %d in message struct %s', sequenceAt, msgStruct)
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                    # See if this is a repeating group and if so, whether we have found the maximum number of occurrences
                    maxOccurs = sequenceList[sequenceAt].attrib['maxOccurs']
                    if maxOccurs == 'unbounded':
                        logger.debug(f'validateXML - tag({groupRef}):unbounded so checking next segment', extra={'raw_message':True})
                        continue        # Continue with the while loop at the start of this routine to check the next segment against this group definition
                    if int(groupOccurs) < int(maxOccurs):
                        logger.debug(f'validateXML - tag({groupRef}):found less than maxOccurs({maxOccurs}) so checking next segment', extra={'raw_message':True})
                        continue        # Continue with the while loop at the start of this routine to check the next segment against this group definition                    
                    # We have found the maximum number of occurrences of this group - move on to the next definition in the sequence
                    # Any further occurences of this group will be treated as unexpected
                    sequenceAt += 1
                    if sequenceAt < len(sequenceList):
                        logger.debug(f'validateXML - tag({groupRef}):more in this node so checking next segment', extra={'raw_message':True})
                        continue
                    return restart, thisElement
                logger.info(f'Nothing returned', extra={'raw_message':True})
                # Nothing found when parsing this group - make sure group itself is optional and skip if it is
                if sequenceList[sequenceAt].attrib['minOccurs'] == '0':
                    sequenceAt += 1
                    continue        #Continue with the while loop at the start of this routine to check this segment against the next definition in the sequence
                return restart, thisElement

            # Not a group, so check if this segment definition defines an optional segment
            if sequenceList[sequenceAt].attrib['minOccurs'] == '0':
                logger.info(f'Node:{sequenceList[sequenceAt].attrib['ref']} is optional - move on', extra={'raw_message':True})
                sequenceAt += 1
                continue
            # This is some sort of failure. There is a defined segment which is required and the current segment is not it.
            # If this sequence is optional [a group, where the first segment in the group will be required], then return what we have
            if optional:
                logger.info(f'tag ({tag}) is optional - return what we have got ({"nothing" if thisElement is None else thisElement.tag})', extra={'raw_message':True})
                return restart, thisElement
            # Otherwise, treat this segment as 'unexpected'
            restart = True
            SegmentStatus[segmentNo] = False
            comment= f'Unexpected Segment, segment {segmentNo + 1:d}: "{Segments[segmentNo]}"'
            print(comment, file=reportFile)
            if not tagged:
                thisElement = et.Element(tag)
                tagged = True
            thisElement.append(et.Comment(comment))
            segmentNo += 1
            return restart, thisElement
        
        # A matching segment - we can validate it and build the matching XML
        logger.debug(f'Node:{sequenceList[sequenceAt].attrib['ref']} is segment {Segments[segmentNo][0:3]}', extra={'raw_message':True})
        seg = Segments[segmentNo][0:3]
        if (lastSeg is None) or (lastSeg != seg):
            lastSeg = seg
            occurs = 0
        if not tagged:      # Create the XML element for this group if we haven't already
            thisElement = et.Element(tag)
            tagged = True
        segElement = et.Element(seg)
        Fields = Segments[segmentNo].split(fieldSep)            # Split this segment into fields
        if Fields[0] == 'MSH':
            Fields.insert(1, fieldSep)
            if escChar == "\\":
                Fields[2] = Fields[2].replace(escChar, "\\\\")
                if "MSH-2" in fieldLengths:
                    fieldLengths["MSH-2"] += 1
        seg = Fields[0]
        Fields = Fields[1:]
        logger.debug(f'Processing segment {seg}, segment {segmentNo + 1:d}, fields {len(Fields)}', extra={'raw_message':True})
        logger.debug(f'Fields: {Fields}', extra={'raw_message':True})
        # Get the definition for the current Segment
        xmlSeg = segmentRoot.find("xsd:complexType[@name='" + seg + ".CONTENT']/xsd:sequence", namespaces)
        if xmlSeg is None:
            logger.critical('XML Schema is missing segment definition for segment %s', seg)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        segData = {}        # The data for any Segment Business rules for this segment
        for i in range(max(len(Fields), len(xmlSeg))):          # Process each field
            fieldCode = f'{seg}-{i + 1:d}'
            if i < len(Fields):
                field = Fields[i].strip()
            # Check that we have enough of a definition to do validation
            if (i < len(xmlSeg)) and ('ref' in xmlSeg[i].attrib) and ('minOccurs' in xmlSeg[i].attrib) and ('maxOccurs' in xmlSeg[i].attrib):
                fieldRef = xmlSeg[i].attrib['ref']
                thisMin = xmlSeg[i].attrib['minOccurs']
                try:
                    fieldMin = int(thisMin)
                except:
                    fieldMin = None
                thisMax = xmlSeg[i].attrib['maxOccurs']
                try:
                    if thisMax == 'unbounded':
                        fieldMax = None
                    else:
                        fieldMax = int(thisMax)
                except:
                    fieldMax = None
                fieldXML = et.Element(fieldRef)
                # Get the field type (datatype) if any
                thisType = fieldRoot.find("xsd:attributeGroup[@name='" + fieldRef + ".ATTRIBUTES']/xsd:attribute[@name='Type']", namespaces)
                if (thisType is not None) and ('fixed' in thisType.attrib):
                    fieldType = thisType.attrib['fixed']
                else:
                    fieldType = None
                # Get any HL7 or User Defined table associated with this field
                thisTable = fieldRoot.find("xsd:attributeGroup[@name='" + fieldRef + ".ATTRIBUTES']/xsd:attribute[@name='Table']", namespaces)
                if (thisTable is not None) and ('fixed' in thisTable.attrib):
                    fieldTable = thisTable.attrib['fixed']
                else:
                    fieldTable = None                    
            else:
                fieldRef = None
                fieldMin = None
                fieldMax = None
                fieldXML = et.Element(fieldCode)
                fieldType = 'ST'
                fieldTable = None
            if (i >= len(Fields)) or (field == ''):         # An empty or missing field
                if (fieldMin is not None) and (fieldMin > 0):
                    comment = f'ERROR: Missing required field [{fieldCode}] in Segment {seg}, segment {segmentNo + 1:d}'
                    print(comment, file=reportFile)
                    fieldXML.append(et.Comment(comment))
                    segElement.append(fieldXML)
                continue
            logger.debug(f'Processing segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, data {field}, fieldRef:{fieldRef}, fieldType:{fieldType}, fieldTable:{fieldTable} ', extra={'raw_message':True})
            if (fieldRef is None) or (fieldType is None):
                if fieldType is None:
                    comment = f'WARNING: Undefined Field in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]'
                else:
                    comment = f'WARNING: Unexpected field in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}-{i + 1:d}, repetition [{j + 1:d}]'
                    print(comment, file=reportFile)
                    fieldXML.append(et.Comment(comment))
                    # Check for illegal characters in the field and remove and report them
                    badChars = XMLclean.finditer(field)
                    if len(list(badChars)) > 0:
                        fieldXML.text = XMLclean.sub(field, '')
                        for badChar in badChars:
                            comment = f'WARNING: Illegal character(s) [{repr(field[badChar.start():badChar.end()])}] at [{badChar.start()}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]'
                            print(comment, file=reportFile)
                            fieldXML.append(et.Comment(comment))
                    else:
                        fieldXML.text = field
                    comment = fixElement(fieldXML, 'ST', None, None, None)
                    if comment is not None:
                        comment += f' in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j + 1:d}]'
                        print(comment, file=reportFile)
                        fieldXML.append(et.Comment(comment))
                    segElement.append(fieldXML)
                    continue
            # Split this field into repetitions - except for the encoding characters and FT data
            if (seg == 'MSH') and (i == 1):
                fieldReps = [field]
            elif fieldType == 'FT':
                fieldReps = [field]
            else:
                fieldReps = field.split(repSep)
            # Set up the counters for any "min" or "max" rules for this field
            fieldRulesPassed = {}        # A dictionary of the counts for any "min" or "max" rules for this field
            if fieldCode in fieldBusinessRules:
                for group in fieldBusinessRules[fieldCode]:
                    if (group is not None) and (group not in previousTags) and (group != tag):
                        continue
                    for rule in fieldBusinessRules[fieldCode][group]:
                        for thisType in fieldBusinessRules[fieldCode][group][rule]:
                            if thisType in ["min", "max"]:
                                if rule not in fieldRulesPassed:
                                    fieldRulesPassed[rule] = {}
                                if group not in fieldRulesPassed[rule]:
                                    fieldRulesPassed[rule][group] = {}
                                fieldRulesPassed[rule][group][thisType] = 0
            # Validate each field repetition of this field and build the XML for each repetition
            for j, thisField in enumerate(fieldReps):
                logger.debug(f'Processing segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], data {thisField}', extra={'raw_message':True})
                if j > 0:           # For repetitions after the first, we need to create a new XML element for this field repetition
                    if fieldRef is None:
                        fieldXML = et.Element(fieldCode)
                    else:
                        fieldXML = et.Element(fieldRef)
                data = {}       # The data for any Field Business rules for this field repetition
                data["Repeat Number"] = j + 1
                if thisField == '""':
                    continue
                if (fieldMax is not None) and (fieldMax <= j):
                    comment = f'WARNING: Unexpected field repeat [{j + 1:d}] in segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}]'
                    print(comment, file=reportFile)
                    fieldXML.append(et.Comment(comment))
                    continue
                if fieldType == 'varies':
                    if (seg == 'OBX') and (fieldRef == 'OBX.5'):
                        fieldType = Fields[1]
                    elif (seg == 'MFE') and (fieldRef == 'MFE.4') and (len(Fields) > 4):
                        fieldType = Fields[4]
                    if fieldType == 'TX':
                        comment = f'WARNING: Invalid data type TX in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j + 1:d}]'
                        print(comment, file=reportFile)
                        fieldXML.append(et.Comment(comment))
                        fieldType = 'ST'
                # Get the component parts definition for this field
                dataTypeBits = dataTypeRoot.find("xsd:complexType[@name='" + fieldType + "']/xsd:sequence", namespaces)
                if fieldType == 'FT':       # FT has a sequence, but not components
                    dataTypeBits = None
                Components = []
                if dataTypeBits is not None:
                    # We can now try and validate the components
                    Components = thisField.split(compSep)
                    for k, component in enumerate(Components):
                        logger.debug(f'Processing segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{k + 1:d}], data {component}', extra={'raw_message':True})
                        if component == '""':
                            continue
                        componentCode = f'{seg}-{i + 1:d}.{k + 1:d}'
                        if (k < len(dataTypeBits)) and ('ref' in dataTypeBits[k].attrib) and ('minOccurs' in dataTypeBits[k].attrib):
                            componentRef = dataTypeBits[k].attrib['ref']
                            thisMin = dataTypeBits[k].attrib['minOccurs']
                            try:
                                componentMin = int(thisMin)
                            except:
                                componentMin = None
                            componentXML = et.Element(componentRef)
                            thisType = dataTypeRoot.find("xsd:attributeGroup[@name='" + componentRef + ".ATTRIBUTES']/xsd:attribute[@name='Type']", namespaces)
                            if (thisType is not None) and ('fixed' in thisType.attrib):
                                componentType = thisType.attrib['fixed']
                            else:
                                componentType = None
                            thisTable = dataTypeRoot.find("xsd:attributeGroup[@name='" + componentRef + ".ATTRIBUTES']/xsd:attribute[@name='Table']", namespaces)
                            if (thisTable is not None) and ('fixed' in thisTable.attrib):
                                componentTable = thisTable.attrib['fixed']
                            else:
                                componentTable = None                    
                        else:
                            componentRef = None
                            componentMin = None
                            componentXML = et.Element(componentCode)
                            componentType = 'ST'
                            componentTable = None
                        if component == '':
                            if (componentMin is not None) and (componentMin > 0):
                                comment = f'WARNING: Missing required component [{componentCode}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repeat [{j + 1:d}]'
                                print(comment, file=reportFile)
                                componentXML.append(et.Comment(comment))
                                fieldXML.append(componentXML)
                            continue
                        if (componentRef is None) or (componentType is None):
                            if componentRef is None:
                                comment = f'WARNING: Unexpected component in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}] - {component}'
                            else:
                                comment = f'WARNING: Undefined component in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]'
                            print(comment, file=reportFile)
                            componentXML.append(et.Comment(comment))
                            # Check for illegal characters in the component and remove and report them
                            badChars = XMLclean.finditer(component)
                            if len(list(badChars)) > 0:
                                componentXML.text = XMLclean.sub(component, '')
                                for badChar in badChars:
                                    comment = f'WARNING: Illegal character(s) [{repr(component[badChar.start():badChar.end()])}] at [{badChar.start()}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]'
                                    print(comment, file=reportFile)
                                    componentXML.append(et.Comment(comment))
                            else:
                                componentXML.text = component
                            comment = fixElement(componentXML, 'ST', fieldType, k + 1, fieldXML)
                            if comment is not None:
                                comment += f' in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j+ 1:d}], component [{componentCode}]'
                                print(comment, file=reportFile)
                                componentXML.append(et.Comment(comment))
                            fieldXML.append(componentXML)
                            continue
                        # Check if this component has defined subcomponents
                        componentBits = dataTypeRoot.find("xsd:complexType[@name='" + componentType + "']/xsd:sequence", namespaces)
                        componentXML = et.Element(componentRef)
                        subComponents = []
                        if (componentBits is not None) and (subCompSep != ''):
                            logger.debug(f'Processing segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponents', extra={'raw_message':True})
                            subComponents = component.split(subCompSep)
                            for l, subComponent in enumerate(subComponents):
                                if subComponent == '""':
                                    continue
                                subCompCode = f'{seg}-{i + 1:d}.{k + 1:d}.{l + 1:d}'
                                if (l < len(componentBits)) and ('ref' in componentBits[l].attrib) and ('minOccurs' in componentBits[l].attrib):
                                    subCompRef = componentBits[l].attrib['ref']
                                    thisMin = componentBits[l].attrib['minOccurs']
                                    try:
                                        subCompMin = int(thisMin)
                                    except:
                                        subCompMin = None
                                    subComponentXML = et.Element(subCompRef)
                                    thisType = dataTypeRoot.find("xsd:attributeGroup[@name='" + subCompRef + ".ATTRIBUTES']/xsd:attribute[@name='Type']", namespaces)
                                    if (thisType is not None) and ('fixed' in thisType.attrib):
                                        subCompType = thisType.attrib['fixed']
                                    else:
                                        subCompType = None                    
                                    thisTable = dataTypeRoot.find("xsd:attributeGroup[@name='" + subCompRef + ".ATTRIBUTES']/xsd:attribute[@name='Table']", namespaces)
                                    if (thisTable is not None) and ('fixed' in thisTable.attrib):
                                        subCompTable = thisTable.attrib['fixed']
                                    else:
                                        subCompTable = None                    
                                else:
                                    subCompRef = None
                                    subCompMin = None
                                    subComponentXML = et.Element(subCompCode)
                                    subCompType = 'ST'
                                    subCompTable = None
                                if subComponent == '':
                                    if (subCompMin is not None) and (subCompMin > 0):
                                        comment = f'ERROR: Missing required subcomponent [{subCompCode}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                        print(comment, file=reportFile)
                                        subComponentXML.append(et.Comment(comment))
                                        componentXML.append(subComponentXML)
                                    continue
                                if (subCompRef is None) or (subCompType is None):
                                    if subCompRef is None:
                                        comment = f'WARNING: Undefined subcomponent [{subCompCode}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]'
                                    else:
                                        comment = f'WARNING: Unexpected subcomponent [{subCompCode}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}] - {subComponent}'
                                    print(comment, file=reportFile)
                                    subComponentXML.append(et.Comment(comment))
                                    # Check for illegal characters in the subcomponent and remove and report them
                                    badChars = XMLclean.finditer(subComponent)
                                    if len(list(badChars)) > 0:
                                        subComponentXML.text = XMLclean.sub(subComponent, '')
                                        for badChar in badChars:
                                            comment = f'WARNING: Illegal character(s) [{repr(subComponent[badChar.start():badChar.end()])}] at [{badChar.start()}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                            print(comment, file=reportFile)
                                            subComponentXML.append(et.Comment(comment))
                                    else:
                                        subComponentXML.text = subComponent
                                    subComponentXML.append(et.Comment(comment))
                                    comment = fixElement(subComponentXML, subCompType, componentType, l + 1, componentXML)
                                    if comment is not None:
                                        comment += f' in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j+ 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                        print(comment, file=reportFile)
                                        subComponentXML.append(et.Comment(comment))
                                    componentXML.append(subComponentXML)
                                    continue
                                # Save this subcomponent for any business rules that may be associated with it
                                logger.debug(f'Saving subcomponent {subComponent} in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]', extra={'raw_message':True})
                                # Save this subcomponent as field.component.subcomponent data
                                if seg in glossary:
                                    if subCompCode in glossary[seg]:
                                        data[subCompCode] = subComponent
                                        if fieldMax is not None:
                                            if subCompCode not in segData:
                                                segData[subCompCode] = []
                                            segData[subCompCode].append(subComponent.replace('\\', '\\\\'))
                                        else:
                                            segData[subCompCode] = subComponent.replace('\\', '\\\\')
                                    else:
                                        logger.debug(f'Subcomponent {subCompCode} not in glossary for segment {seg}', extra={'raw_message':True})
                                # Save this subcompoent as datatype data
                                if componentType in glossary:
                                    if f'{componentType}.{l + 1:d}' in glossary[componentType]:
                                        data[f'{componentType}.{l + 1:d}'] = subComponent
                                    else:
                                        logger.debug(f'Subcomponent {componentType}.{l + 1:d} not in glossary for datatype {componentType}', extra={'raw_message':True})
                                if fieldType in glossary:
                                    if f'{fieldType}.{k + 1:d}.{l + 1:d}' in glossary[fieldType]:
                                        data[f'{fieldType}.{k + 1:d}.{l + 1:d}'] = subComponent
                                    else:
                                        logger.debug(f'Subcomponent {fieldType}.{k + 1:d}.{l + 1:d} not in glossary for datatype {fieldType}', extra={'raw_message':True})
                                # Check for illegal characters in the subcomponent and remove and report them
                                subComponentXML.text = subComponent
                                logger.debug(f'Adding subcomponent {subComponent} to XML for segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]', extra={'raw_message':True})
                                badChars = XMLclean.finditer(subComponent)
                                if len(list(badChars)) > 0:
                                    subComponentXML.text = XMLclean.sub(subComponent, '')
                                    for badChar in badChars:
                                        comment = f'WARNING: Illegal character(s) [{repr(subComponent[badChar.start():badChar.end()])}] at [{badChar.start()}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                        print(comment, file=reportFile)
                                        subComponentXML.append(et.Comment(comment))
                                comment = fixElement(subComponentXML, subCompType, componentType, l + 1, componentXML)
                                if comment is not None:
                                    comment += f' in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j+ 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                    print(comment, file=reportFile)
                                    subComponentXML.append(et.Comment(comment))
                                # Check the subcomponent/component/field tables for this subcomponent
                                # This subcomponent could be in any one of three tables - the subcomponent table, the component table or the field table.
                                # Or all three table could be undefined, in which case this subcomoponent passes table checking.
                                # However, if any of the three tables are defined, then this subcomponent isn't in any of them, then we have to report all tables tested.
                                inTable = None
                                testedTables = []
                                logger.debug(f'Checking subcomponent "{subComponent}" in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}] against subCompTable:{subCompTable}, componentTable:{componentTable}, fieldTable:{fieldTable}', extra={'raw_message':True})
                                if (subCompTable is not None) and (hl7Tables is not None):
                                    if subCompTable in hl7Tables:
                                        testedTables.append(f'{hl7Tables[subCompTable]["type"]} {subCompTable}')
                                        if subComponent not in hl7Tables[subCompTable]['codes']:
                                            inTable = False
                                        else:
                                            inTable = True
                                    else:
                                        testedTables.append(f'{subCompTable}')
                                        inTable = False
                                # Check if this is the first subcomponent
                                if (l == 0) and (componentTable is not None) and (hl7Tables is not None):
                                    if componentTable in hl7Tables:
                                        testedTables.append(f'{hl7Tables[componentTable]["type"]} {componentTable}')
                                        if subComponent not in hl7Tables[componentTable]['codes']:
                                            if inTable is None:
                                                inTable = False
                                        else:
                                            inTable = True
                                    else:
                                        testedTables.append(f'{componentTable}')
                                        inTable = False
                                # Check if this is the first subcomponent in the first component
                                if (l == 0) and (k == 0) and (fieldTable is not None) and (hl7Tables is not None):
                                    if fieldTable in hl7Tables:
                                        testedTables.append(f'{hl7Tables[fieldTable]["type"]} {fieldTable}')
                                        if subComponent not in hl7Tables[fieldTable]['codes']:
                                            if inTable is None:
                                                inTable = False
                                        else:
                                            inTable = True
                                    else:
                                        testedTables.append(f'{fieldTable}')
                                        inTable = False
                                if inTable is False:
                                    if len(testedTables) == 1:
                                        comment = f'COMMENT: Illegal value "{subComponent}" - not in {testedTables[0]} table in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                    else:
                                        comment = f'COMMENT: Illegal value "{subComponent}" - not in {"/".join(testedTables)} tables in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                    print(comment, file=reportFile)
                                    subComponentXML.append(et.Comment(comment))
                                # Check if there is a subcomponent length
                                if (datatypeLengths is not None) and (subCompType in datatypeLengths) and (l in datatypeLengths[subCompType]):
                                    if len(subComponent) > datatypeLengths[subCompType][l]:
                                        comment = f'WARNING: Illegally long subcomponent - "{subComponent}" in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j + 1:d}], component [{componentCode}], subcomponent [{subCompCode}]'
                                        print(comment, file=reportFile)
                                        subComponentXML.append(et.Comment(comment))
                                # Check value sets for this subcomponent if it is a coding system
                                if (componentType in ['CE', 'CNE', 'CWE']) and (valueSets is not None) and (l in [2, 5]) and (componentCode in valueSets) and (subComponent in valueSets[componentCode]):
                                    # We have one or more value sets for component, with this value set system. Check each group to see if this segment is in that group.
                                    # If so, check that the identifiers is in thisvalue set.
                                    for group in valueSets[componentCode][subComponent]:
                                        if (group is None) or (group in previousTags) or (group == tag):
                                            if subComponents[l - 2] not in valueSets[componentCode][subComponent][group]:
                                                comment = f'COMMENT: Identifier "{subComponents[l - 2]}" not in coding system "{subComponent}" in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component[{componentCode}]'
                                                print(comment, file=reportFile)
                                                subComponentXML.append(et.Comment(comment))
                                            elif (valueSets[componentCode][subComponent][group][subComponents[l - 2]] is not None) and (subComponents[l - 1] not in valueSets[componentCode][subComponent][group][subComponents[l - 2]]):
                                                comment = f'COMMENT: Description "{subComponents[l - 1]}" not valid for Identifier "{subComponents[l - 2]}" in coding system "{subComponent}" in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component[{componentCode}]'
                                                print(comment, file=reportFile)
                                                subComponentXML.append(et.Comment(comment))
                                # End of this subcomponent
                                componentXML.append(subComponentXML)
                        else:       # No subcomponents - just validate this component
                            # Save this component for any business rules that may be associated with it
                            logger.debug(f'Saving component {component} in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]', extra={'raw_message':True})
                            # Save this component as field data
                            if seg in glossary:
                                if fieldCode in glossary[seg]:
                                    data[fieldCode] = thisField
                                    if fieldMax is not None:
                                        if fieldCode not in segData:
                                            segData[fieldCode] = []
                                        segData[fieldCode].append(thisField.replace('\\', '\\\\'))
                                    else:
                                        segData[fieldCode] = thisField.replace('\\', '\\\\')
                                else:
                                    logger.debug(f'Field {fieldCode} not in glossary for segment {seg}', extra={'raw_message':True})
                            if seg in glossary:
                                if componentCode in glossary[seg]:
                                    data[componentCode] = component
                                    if fieldMax is not None:
                                        if componentCode not in segData:
                                            segData[componentCode] = []
                                        segData[componentCode].append(component.replace('\\', '\\\\'))
                                    else:
                                        segData[componentCode] = component.replace('\\', '\\\\')
                                else:
                                    logger.debug(f'Component {componentCode} not in glossary for segment {seg}', extra={'raw_message':True})
                            # Save this component as datatype data
                            if fieldType in glossary:
                                if f'{fieldType}.{k + 1:d}' in glossary[fieldType]:
                                    data[f'{fieldType}.{k + 1:d}'] = component
                                else:
                                    logger.debug(f'Component {fieldType}.{k + 1:d} not in glossary for datatype {fieldType}', extra={'raw_message':True})
                            # Check for illegal characters in the component and remove and report them
                            logger.debug(f'Adding component {component} to XML for segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]', extra={'raw_message':True})
                            componentXML.text = component
                            badChars = XMLclean.finditer(component)
                            if len(list(badChars)) > 0:
                                componentXML.text = XMLclean.sub(component, '')
                                for badChar in badChars:
                                    comment = f'WARNING: Illegal character(s) [{repr(component[badChar.start():badChar.end()])}] at [{badChar.start()}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]'
                                    print(comment, file=reportFile)
                                    componentXML.append(et.Comment(comment))
                            comment = fixElement(componentXML, componentType, fieldType, i + 1, fieldXML)
                            if comment is not None:
                                comment += f' in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j + 1:d}], component [{componentCode}]'
                                print(comment, file=reportFile)
                                componentXML.append(et.Comment(comment))
                            # Check the component/field tables for this component
                            # This component could be in any one of two tables - the component table or the field table.
                            # Or both tables could be undefined, in which case this comoponent passes table checking.
                            # However, if any of the two tables are defined, and this component isn't in any of them, then we have to report all tables tested.
                            inTable = None
                            testedTables = []
                            logger.debug(f'Checking component "{component}" in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}] against componentTable:{componentTable}, fieldTable:{fieldTable}', extra={'raw_message':True})
                            # Check this subcomponent
                            if (componentTable is not None) and (hl7Tables is not None):
                                if componentTable in hl7Tables:
                                    testedTables.append(f'{hl7Tables[componentTable]["type"]} {componentTable}')
                                    if component not in hl7Tables[componentTable]['codes']:
                                        inTable = False
                                    else:
                                        inTable = True
                                else:
                                    testedTables.append(f'{componentTable}')
                                    inTable = False
                            # Check if this is the first subcomponent in the first component
                            if (k == 0) and (fieldTable is not None) and (hl7Tables is not None):
                                if fieldTable in hl7Tables:
                                    testedTables.append(f'{hl7Tables[fieldTable]["type"]} {fieldTable}')
                                    if component not in hl7Tables[fieldTable]['codes']:
                                        if inTable is None:
                                            inTable = False
                                    else:
                                        inTable = True
                                else:
                                    testedTables.append(f'{fieldTable}')
                                    if inTable is None:
                                        inTable = False
                            if inTable is False:
                                if len(testedTables) == 1:
                                    comment = f'COMMENT: Illegal value "{component}" - not in {testedTables[0]} table in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]'
                                else:
                                    comment = f'COMMENT: Illegal value "{component}" - not in {"/".join(testedTables)} tables in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component [{componentCode}]'
                                print(comment, file=reportFile)
                                componentXML.append(et.Comment(comment))
                            # Check the component length                           
                            if (datatypeLengths is not None) and (componentType in datatypeLengths) and (k in datatypeLengths[componentType]):
                                if len(component) > datatypeLengths[componentType][k]:
                                    comment = f'WARNING: Illegally long component - "{component}" in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j + 1:d}], component [{componentCode}]'
                                    print(comment, file=reportFile)
                                    componentXML.append(et.Comment(comment))
                            # Check value sets for this component if it is a coding system
                            if (fieldType in ['CE', 'CNE', 'CWE']) and (valueSets is not None) and (k in [2, 5]) and (fieldCode in valueSets) and (component in valueSets[fieldCode]):
                                # We have one or more value sets for this component, with this value set system.
                                # Check each group to see if this segment is in that group.
                                # If so, check that the identifiers is in this value set.
                                for group in valueSets[fieldCode][component]:
                                    if (group is None) or (group in previousTags) or (group == tag):
                                        if Components[k - 2] not in valueSets[fieldCode][component][group]:
                                            comment = f'COMMENT: Identifier "{Components[k - 2]}" not in coding system "{component}" in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]'
                                            print(comment, file=reportFile)
                                            componentXML.append(et.Comment(comment))
                                        elif (valueSets[fieldCode][component][group][Components[k - 2]] is not None) and (Components[k - 1] not in valueSets[fieldCode][component][group][Components[k - 2]]):
                                            comment = f'COMMENT: Description "{Components[k - 1]}" not valid for Identifier "{Components[k - 2]}" in coding system "{component}" in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]'
                                            print(comment, file=reportFile)
                                            componentXML.append(et.Comment(comment))
                        if componentType in dataTypeBusinessRules:
                            for group in dataTypeBusinessRules[componentType][rule]:
                                if (group is not None) and (group not in previousTags) and (group != tag):
                                    continue
                                for segment in dataTypeBusinessRules[componentType][rule][group]:
                                    if (segment is not None) and (segment != seg):
                                        continue
                                    for rule in dataTypeBusinessRules[componentType][rule][group][segment]:
                                        data['Rule'] = rule
                                        logger.debug(f'Checking Business Datatype Rule({rule}) with data {data}', extra={'raw_message':True})
                                        (status, newData) = rulesEngine.decide(data)
                                        if 'errors' in status:
                                            logger.critical('Critical Error(s) in Rules Definitions in Data Type Rules for rule (%s)', rule)
                                            for thisError in status['errors']:
                                                logger.critical('%s', thisError)
                                            logging.shutdown()
                                            sys.exit(EX_CONFIG)
                                        if isinstance(newData, list):
                                            if len(newData) == 0:
                                                logger.critical('Critical Error in Rules Definitions in Data Type Rules for rule (%s) - no Decision Table executed', rule)
                                                logging.shutdown()
                                                sys.exit(EX_CONFIG)
                                            Result = newData[-1]['Result']
                                        else:
                                            Result = newData['Result']
                                        if Result['Passed'] == False:
                                            comment = f'{Result["Reason"]} - Datatype Rule ({rule}), dataType({componentType}) - Testing failure in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], component {componentCode}, component data ({component})'
                                            print(comment, file=reportFile)
                                            componentXML.append(et.Comment(comment))
                        # End of this component
                        fieldXML.append(componentXML)
                else:
                    # Save this field for any business rules that may be associated with it
                    logger.debug(f'Saving field {thisField} in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]', extra={'raw_message':True})    
                    if (seg in glossary) and (fieldCode in glossary[seg]):
                        data[fieldCode] = thisField
                        if fieldMax is not None:
                            if fieldCode not in segData:
                                segData[fieldCode] = []
                            segData[fieldCode].append(thisField.replace('\\', '\\\\'))
                        else:
                            segData[fieldCode] = thisField.replace('\\', '\\\\')
                    logger.debug(f'Adding field {thisField} to XML for segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]', extra={'raw_message':True})
                    fieldXML.text = thisField
                    badChars = XMLclean.finditer(thisField)
                    if len(list(badChars)) > 0:
                        fieldXML.text = XMLclean.sub(thisField, '')
                        for badChar in badChars:
                            comment = f'WARNING: Illegal character(s) [{repr(thisField[badChar.start():badChar.end()])}] at [{badChar.start()}] in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]'
                            print(comment, file=reportFile)
                            fieldXML.append(et.Comment(comment))
                    comment = fixElement(fieldXML, fieldType, None, None, None)
                    if comment is not None:
                        comment += f' in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j + 1:d}]'
                        print(comment, file=reportFile)
                        fieldXML.append(et.Comment(comment))
                    # Check field table and field length
                    logger.debug(f'Checking field "{thisField}" in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}] against fieldTable {fieldTable}', extra={'raw_message':True})
                    if (fieldTable is not None) and (hl7Tables is not None):
                        if fieldTable in hl7Tables:
                            if thisField not in hl7Tables[fieldTable]['codes']:
                                comment = f'WARNING:Illegal value "{thisField}" - not in table {hl7Tables[fieldTable]["type"]} {fieldTable} in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]'
                                print(comment, file=reportFile)
                                fieldXML.append(et.Comment(comment))
                        else:
                            comment = f'WARNING:Illegal value "{thisField}" - not in table {fieldTable} in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}]'
                            print(comment, file=reportFile)
                            fieldXML.append(et.Comment(comment))
                    if (fieldLengths is not None) and (fieldCode in fieldLengths) and (fieldLengths[fieldCode] not in [999999, 65356]):
                        if len(thisField) > fieldLengths[fieldCode]:
                            comment = f'WARNING: Illegally long field - "{thisField}" in Segment {seg}, segment {segmentNo + 1:d} in field [{fieldCode}], repetition [{j + 1:d}]'
                            print(comment, file=reportFile)
                            fieldXML.append(et.Comment(comment))
                if fieldType in dataTypeBusinessRules:
                    for group in dataTypeBusinessRules[fieldType]:
                        if (group is not None) and (group not in previousTags) and (group != tag):
                            continue
                        for segment in dataTypeBusinessRules[fieldType][group]:
                            if (segment is not None) and (segment != seg):
                                continue
                            for rule in dataTypeBusinessRules[fieldType][group][segment]:
                                data["Rule"] = rule
                                logger.debug(f'Checking Business Datatype Rule({rule}) with data {data}', extra={'raw_message':True})
                                (status, newData) = rulesEngine.decide(data)
                                if 'errors' in status:
                                    logger.critical('Critical Error(s) in Rules Definitions in Data Type Rules for rule (%s)', rule)
                                    for thisError in status['errors']:
                                        logger.critical('%s', thisError)
                                    logging.shutdown()
                                    sys.exit(EX_CONFIG)
                                if isinstance(newData, list):
                                    if len(newData) == 0:
                                        logger.critical('Critical Error in Rules Definitions in Data Type Rules for rule (%s) - no Decision Table executed', rule)
                                        logging.shutdown()
                                        sys.exit(EX_CONFIG)
                                    Result = newData[-1]['Result']
                                else:
                                    Result = newData['Result']
                                if Result['Passed'] == False:
                                    comment = f'{Result["Reason"]} - Datatype Rule ({rule}), dataType({fieldType}) - Testing failure in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], field data ({thisField})'
                                    print(comment, file=reportFile)
                                    fieldXML.append(et.Comment(comment))
                # End if this field repetition
                segElement.append(fieldXML)
                # Test the field business rules - if any - for this field
                if fieldCode in fieldBusinessRules:      # We have one or more busines rule
                    for group in fieldBusinessRules[fieldCode]:
                        if (group is not None) and (group not in previousTags) and (group != tag):
                            continue
                        for rule in fieldBusinessRules[fieldCode][group]:
                            data["Rule"] = rule
                            logger.debug(f'Checking Business Field Rule({rule}) with data {data}', extra={'raw_message':True})
                            (status, newData) = rulesEngine.decide(data)
                            if 'errors' in status:
                                logger.critical('Critical Error(s) in Rules Definitions in Field Business Rules for rule (%s)', rule)
                                for thisError in status['errors']:
                                    logger.critical('%s', thisError)
                                logging.shutdown()
                                sys.exit(EX_CONFIG)
                            if isinstance(newData, list):
                                if len(newData) == 0:
                                    logger.critical('Critical Error in Rules Definitions in Field Business Rules for rule (%s) - no Decision Table executed', rule)
                                    logging.shutdown()
                                    sys.exit(EX_CONFIG)
                                Result = newData[-1]['Result']
                            else:
                                Result = newData['Result']
                            if rule in fieldRulesPassed:
                                if group in fieldRulesPassed[rule]:
                                    if Result['Passed'] == True:
                                        for thisType in fieldRulesPassed[rule][group]:
                                            fieldRulesPassed[rule][group][thisType] += 1
                            if (Result['Passed'] == False) and ('all' in fieldBusinessRules[fieldCode][group][rule]):
                                comment = f'{Result["Reason"]} - Field Business Rule ({rule}) Testing failure in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode}, repetition [{j + 1:d}], field data ({thisField})'
                                print(comment, file=reportFile)
                                fieldXML.append(et.Comment(comment))

            # End of these field repetitions - end of this field - check the counts in any "min"/"max" business rules for this field
            for rule in fieldRulesPassed:
                for group in fieldRulesPassed[rule]:
                    for thisType in fieldRulesPassed[rule][group]:
                        if (thisType == 'max') and (fieldRulesPassed[rule][group][thisType] > fieldBusinessRules[fieldCode][group][rule]['max']):
                            comment = f'ERROR: Business Rule (rule {rule}:ruleType {thisType}) Testing failure in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode} - {fieldRulesPassed[rule][group][thisType]} valid repetitions > {fieldBusinessRules[fieldCode][group][rule]['max']}'
                            print(comment, file=reportFile)
                            fieldXML.append(et.Comment(comment))
                        elif (thisType == 'min') and (fieldRulesPassed[rule][group][thisType] < fieldBusinessRules[fieldCode][group][rule]['min']):
                            comment = f'ERROR: Business Rule (rule {rule}:ruleType {thisType}) Testing failure in Segment {seg}, segment {segmentNo + 1:d}, field {fieldCode} - {fieldRulesPassed[rule][group][thisType]} valid repetitions < {fieldBusinessRules[fieldCode][group][rule]['min']}'
                            print(comment, file=reportFile)
                            fieldXML.append(et.Comment(comment))
        # End of this segment

        # Test the segment business rules - if any - for this segment
        if seg in segmentBusinessRules:
            for group in segmentBusinessRules[seg]:
                if (group is not None) and (group not in previousTags) and (group != tag):
                    continue
                for rule in segmentBusinessRules[seg][group]:
                    for repeatFields in segmentBusinessRules[seg][group][rule]:
                        if repeatFields is None:    # No repeating fields
                            data = copy.copy(segData)
                            data['Rule'] = rule
                            logger.debug(f'Checking Business Segment Rule({rule}) with data {data}', extra={'raw_message':True})
                            (status, newData) = rulesEngine.decide(data)
                            if 'errors' in status:
                                logger.critical('Critical Error(s) in Rules Definitions in Segment Business Rules for rule (%s)', rule)
                                for thisError in status['errors']:
                                    logger.critical('%s', thisError)
                                logging.shutdown()
                                sys.exit(EX_CONFIG)
                            if isinstance(newData, list):
                                if len(newData) == 0:
                                    logger.critical('Critical Error in Rules Definitions in Segment Business Rules for rule (%s) - no Decision Table executed', rule)
                                    logging.shutdown()
                                    sys.exit(EX_CONFIG)
                                Result = newData[-1]['Result']
                            else:
                                Result = newData['Result']
                            if Result['Passed'] == False:
                                comment = f'{Result["Reason"]} - Segment Business Rule ({rule}) Testing failure in Segment {seg}, segment {segmentNo + 1:d}'
                                print(comment, file=reportFile)
                                segElement.append(et.Comment(comment))
                            else:
                                if 'max' in segmentBusinessRules[seg][group][rule][repeatFields]:
                                    segmentBusinessRules[seg][group][rule][repeatFields]['max']['passed'] += 1
                                elif 'min' in segmentBusinessRules[seg][group][rule][repeatFields]:
                                    segmentBusinessRules[seg][group][rule][repeatFields]['min']['passed'] += 1
                        else:
                            # Execute this rule once for each repeat in the first repeating field
                            repFields = list(repeatFields)
                            if repFields[0] in segData:     # We have this repeat in this segment
                                passed = False
                                for repNo in range(len(segData[repFields[0]])):
                                    data = copy.copy(segData)
                                    data['Rule'] = rule
                                    data['Repeat Number'] = repNo + 1
                                    for repField in repFields:
                                        if (repField in segData) and (repNo < len(segData[repField])):
                                            data[repField] = segData[repField][repNo]
                                    logger.debug(f'Checking Business Segment Rule({rule}) with data {data}', extra={'raw_message':True})
                                    (status, newData) = rulesEngine.decide(data)
                                    if 'errors' in status:
                                        logger.critical('Critical Error(s) in Rules Definitions in Segment Business Rules for rule (%s)', rule)
                                        for thisError in status['errors']:
                                            logger.critical('%s', thisError)
                                        logging.shutdown()
                                        sys.exit(EX_CONFIG)
                                    if isinstance(newData, list):
                                        if len(newData) == 0:
                                            logger.critical('Critical Error in Rules Definitions in Segment Business Rules for rule (%s) - no Decision Table executed', rule)
                                            logging.shutdown()
                                            sys.exit(EX_CONFIG)
                                        Result = newData[-1]['Result']
                                    else:
                                        Result = newData['Result']
                                    if Result['Passed'] == True:
                                        passed = True
                                    else:
                                        if None in segmentBusinessRules[seg][group][rule][repeatFields]:
                                            comment = f'{Result["Reason"]} - Segment Business Rule ({rule}) Testing failure in Segment {seg}, segment {segmentNo + 1:d}'
                                            print(comment, file=reportFile)
                                            segElement.append(et.Comment(comment))
                                if passed:
                                    if 'max' in segmentBusinessRules[seg][group][rule][repeatFields]:
                                        segmentBusinessRules[seg][group][rule][repeatFields]['max']['passed'] += 1
                                    elif 'min' in segmentBusinessRules[seg][group][rule][repeatFields]:
                                        segmentBusinessRules[seg][group][rule][repeatFields]['min']['passed'] += 1

        # Add this segment element to the XML message                                
        thisElement.append(segElement)
        segmentNo += 1

        if segmentNo == len(Segments):
            logger.debug(f'validateXML from tag({tag}):return - no more segments', extra={'raw_message':True})
            return restart, thisElement
        if isChoice:
            logger.debug(f'validateXML from tag({tag}):isChoice is True', extra={'raw_message':True})
            return restart, thisElement
        occurs += 1
        maxOccurs = sequenceList[sequenceAt].attrib['maxOccurs']
        if maxOccurs == 'unbounded':
            logger.debug(f'validateXML - tag({tag}):unbounded so checking next segment', extra={'raw_message':True})
            continue
        if int(occurs) < int(maxOccurs):
            logger.debug(f'validateXML - tag({tag}):found less than maxOccurs({maxOccurs}) so checking next segment', extra={'raw_message':True})
            continue
        sequenceAt += 1
        if sequenceAt < len(sequenceList):
            logger.debug(f'validateXML - tag({tag}):more in this node so checking next segment', extra={'raw_message':True})
            continue
    return restart, thisElement


def fixElement(thisElement, textType, parentType, parentSequence, parentXML):
    '''
    Fix the text associated with thisElement
    '''
    elementText = thisElement.text
    logger.debug(f'fixElement: thisElement.tag({thisElement.tag}), textType({textType}), parentType({parentType}), parentSequence({parentSequence}), elementText({elementText})', extra={'raw_message':True})

    # Check for deleted data
    if elementText == '""':
        return None
    # Check for missing data
    if elementText == '':
        return None
    if elementText is None:
        return None

    # Check some known patterns
    if textType == 'DT':            # Check that this is a correctly formatted date
        if DTpattern.search(elementText) is None:
            return f'Illegally formated date "{elementText}"'
        return None
    if textType == 'DTM':           # Check that this is a correctly formatted date/time
        if DTMpattern.search(elementText) is None:
            return f'Illegally formatted date/time "{elementText}"'
        return None
    if (parentType == 'ED') and (parentSequence == 4):          # Check that this is correclty formatted encoding
        if elementText not in ['Hex', 'Base64']:
            return f'Illegal Encapsulated Data encoding "{elementText}"'
        return None
    if (parentType == 'ED') and (parentSequence == 5):          # Check that this is correclty formatted Hex or Base64 encoded data
        if parentXML is None:
            return None
        ED4 = parentXML.find("ED.4", namespaces)
        if ED4 is None:
            return None
        encoding = ED4.text
        if encoding is None:
            return None
        if encoding == 'Hex':
            if ((len(elementText) % 2) != 0) or (Hexpattern.search(elementText) is None):
                return f'Illegally formated Hex data'
        elif ((len(elementText) % 4) != 0) or (Base64pattern.search(elementText) is None):
            return f'Illegally formated Base64 encoded data'
        return None       
    if textType == 'NM':            # Check that this is a corractly formatted number
        if NMpattern.search(elementText) is None:
            return(f'Illegally formatted number "{elementText}"')
        return None
    if (parentType == 'RI') and (parentSequence == 2):          # Check that this is a correctly formatted time interval
        if RI2pattern.search(elementText) is None:
            return f'Illegally formatted time interval "{elementText}"'
        return None
    if textType == 'SI':            # Check that this is a correctly formatted sequence identifier
        if SIpattern.search(elementText) is None:
            return f'Illegally formatted sequence identifier "{elementText}"'
        return None
    if textType == 'SN.1':          # Check that this is a correctly formatted structure numeric comparitor
        if elementText not in ['<', '>', '=', '<=', '>=', '<>']:
            return f'Illegally formatted numeric comparitor "{elementText}"'
        return None
    if (parentType == 'SN') and (parentSequence == 3):          # Check that this is a correctly formatted numeric separator/suffix
        if (len(elementText) > 1) or (elementText not in '+-/.:'):
            return f'Illegally formatted numeric separator/suffix "{elementText}"'
        return None
    if textType == 'TM':            # Check that this is a correctly formatted time
        if TMpattern.search(elementText) is None:
            return f'Illegally formatted time "{elementText}"'
        return None
    if textType == 'TN':            # Check that this is a correctly formatted telephone number
        if TNpattern.search(elementText) is None:
            return f'Illegally formatted telephone number "{elementText}"'
        return None
    if (parentType == 'TS') and (parentSequence == 1):          # Check that this is a correctly formatted timestamp [DTM]
        if DTMpattern.search(elementText) is None:
            return f'Illegally formatted date/time "{elementText}"'
        return None
    if (parentType == 'TS') and (parentSequence == 2):          # Check that this is a correctly formatted time degree of precision
        if TS2pattern.search(elementText) is None:
            return f'Illegally formatted time degree of precission "{elementText}"'
        return None
    if (parentType == 'XTN') and (parentSequence == 1):         # Check that this is a correctly formatted telephone number [TN]
        if TNpattern.search(elementText) is None:
            return f'Illegally formatted telephone number "{elementText}"'
        return None

    '''
    We may need to add child element like <escape ... />
    The tail of thisElement will be the text up to the <escape ... />
    and the remaining text will be the tail of the child <escape ... /> tag
    '''
    if textType not in ['TX', 'FT', 'CF']:
        return None
    while (charRef := charXref.search(elementText)) is not None:
        chars = charRef.group()[2:-1]
        repChars = ''
        for cp in range(0, len(chars), 2):
            repChars += r'&#x' + chars[cp:cp + 2] + ';'
        elementText = elementText[0:charRef.start()] + repChars + elementText[charRef.end():]
    while (charRef := charZref.search(elementText)) is not None:
        chars = charRef.group()[2:-1]
        repChars = ''
        for cp in range(0, len(chars), 2):
            repChars += r'&#x' + chars[cp:cp + 2] + ';'
        elementText = elementText[0:charRef.start()] + repChars + elementText[charRef.end():]
    thisElement.text = elementText
    firstEscape = None
    for replacement in xmlReplacements:
        if (found := replacement.search(elementText)) is not None:
            if (firstEscape is None) or (found.start() < firstEscape):
                firstEscape = found.start()
                firstEnd = found.end()
                firstGroup = found.group()
    if firstEscape is None:
        return None
    thisElement.text = elementText[:firstEscape]
    escapeElement = et.Element('escape')
    escapeElement.attrib['V'] = firstGroup[1:-1]
    escapeElement.tail = elementText[firstEnd:]
    thisElement.append(escapeElement)
    lastEscapeElement = escapeElement
    escapeElementTail = escapeElement.tail
    while True:
        nextEscape = None
        for replacement in xmlReplacements:
            if (found := replacement.search(escapeElementTail)) is not None:
                if (nextEscape is None) or (found.start() < nextEscape):
                    nextEscape = found.start()
                    nextEnd = found.end()
                    nextGroup = found.group()
        if nextEscape is None:
            return None
        lastEscapeElement.tail = escapeElementTail[:nextEscape]
        escapeElement = et.Element('escape')
        escapeElement.attrib['V'] = nextGroup[1:-1]
        escapeElement.tail = escapeElementTail[nextEnd:]
        thisElement.append(escapeElement)
        lastEscapeElement = escapeElement
        escapeElementTail = escapeElement.tail
    return None


# Define a logging Formatter class
# To suppress program/level/datetime at the start of a logging record use
# logger.xxxx('message', extra={'raw_message':True})
class ConditionalFormatter(logging.Formatter):
    def format(self, record):
        if hasattr(record, 'raw_message') and record.raw_message:
            return record.getMessage()
        else:
            return super().format(record)


if __name__ == '__main__':
    '''
    The main code
    Start by parsing the command line arguements and setting up logging.
    Then process each message - get the HL7 v2.x vertical bar message and convert it an HL7 v2.xml XML tagged message.
    During this process we will validate the message against the matching HL7 v2.xml schema and Appendix A data,
    plus test that the message meets any business rules defined in the HL7 v2.x Business Rules Definitions
    ('Business Rules.xlsx' and 'Business Rules DMN.xlsx').
    '''

    # Set the command line options
    progName = sys.argv[0]
    progName = progName[0:-3]        # Strip off the .py ending
    parser = argparse.ArgumentParser(description='hl7Validator')
    parser.add_argument('-I', '--inputDir', dest='inputDir', default='input', metavar='inputDir',
                        help='The folder containing the HL7 v2.x vertical bar encoded message files')
    parser.add_argument('-i', '--inputFile', dest='inputFile',
                        help='The name of the HL7 v2.x vertical bar encoded message file')
    parser.add_argument ('-R', '--reportDir', dest='reportDir', default='reports', metavar='reportDir',
                         help='The name of the directory where the report(s) file will be created (default="reports")')
    parser.add_argument('-O', '--outputDir', dest='outputDir', default='output', metavar='outputDir',
                        help='The folder where the HL7 v2.xml XML tagged message(s) will be created (default="output")')
    parser.add_argument('-S', '--schemaDir', dest='schemaDir', required=True, metavar='schemaDir',
                        help='The folder containing the HL7 v2.xml XML schema files (e.g. "schema/v2.4")')
    parser.add_argument ('-v', '--verbose', dest='verbose', type=int, choices=range(0,5),
                         help='The level of logging\n\t0=CRITICAL,1=ERROR,2=WARNING,3=INFO,4=DEBUG')
    parser.add_argument ('-L', '--logDir', dest='logDir', default='.', metavar='logDir',
                         help='The name of the directory where the logging file will be created')
    parser.add_argument ('-l', '--logFile', dest='logFile', metavar='logfile', help='The name of a logging file')

    # Parse the command line
    args = parser.parse_args()
    inputDir = args.inputDir
    inputFile = args.inputFile
    reportDir = args.reportDir
    outputDir = args.outputDir
    schemaDir = args.schemaDir
    logDir = args.logDir
    logFile = args.logFile
    loggingLevel = args.verbose

    # Set up logging
    loggingLevels = {0:logging.CRITICAL, 1:logging.ERROR, 2:logging.WARNING, 3:logging.INFO, 4:logging.DEBUG}
    logger = logging.getLogger(__name__)
    if args.verbose:
        logger.setLevel(loggingLevels[args.verbose])
    else:
        logger.setLevel(logging.WARNING)
    if args.logFile:
        handler = logging.FileHandler(os.path.join(args.logDir, args.logFile), mode='w')
    else:
        handler = logging.StreamHandler()
    logformat = progName + ' %(levelname)s[%(asctime)s]: %(message)s'
    dateformat = '%d/%m/%y'
    formatter = ConditionalFormatter(logformat, dateformat)
    handler.setFormatter(formatter)
    logger.addHandler(handler)

    # Check that the schemaDir folder exist and read in the segment, fields and datatype schemas
    if not os.path.isdir(schemaDir):
        logger.critical('No schemaDir folder named "%s"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if not os.path.isdir(os.path.join(schemaDir, 'xsd')):
        logger.critical('No schemaDir folder named "%s/xsd"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if not os.path.isfile(os.path.join(schemaDir, 'xsd', 'segments.xsd')):
        logger.critical('No file "segments.xsd" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    segmentTree = et.parse(os.path.join(schemaDir, 'xsd', 'segments.xsd'))
    segmentRoot = segmentTree.getroot()
    if not os.path.isfile(os.path.join(schemaDir, 'xsd', 'fields.xsd')):
        logger.critical('No file "fields.xsd" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    fieldTree = et.parse(os.path.join(schemaDir, 'xsd', 'fields.xsd'))
    fieldRoot = fieldTree.getroot()
    if not os.path.isfile(os.path.join(schemaDir, 'xsd', 'datatypes.xsd')):
        logger.critical('No file "datatypes.xsd" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    dataTypeTree = et.parse(os.path.join(schemaDir, 'xsd', 'datatypes.xsd'))
    dataTypeRoot = dataTypeTree.getroot()
    namespaces={'xsd':'http://www.w3.org/2001/XMLSchema'}

    # Load the Appendix A data
    getAppendixA(schemaDir)

    # Load any datatype data
    getDatatypes(schemaDir)

    # Load any value sets
    getValueSets(schemaDir)

    # Load any Business Rules
    getBusinessRules(schemaDir)


    # If inputFile is specified and is '-', then read one HL7 v2.x vertical bar encoded message from standard input
    # If inputFile is specified and is not '-', and inputDir is None then read one HL7 v2.x vertical bar encoded message from ./inputFile.
    # If inputFile is specified and is not '-', and inputDir is not None then read one HL7 v2.x vertical bar encoded message from inputDir/inputFile.
    # If both inputFile and inputDir are not specified, then read one HL7 v2.x vertical bar encoded message from standard input.
    # If inputFile is not specified, but inputDir is specified, then read one HL7 v2.x vertical bar encoded message for every file in inputDir.

    # If one HL7 v2.x vertical bar encoded message is read from standard input, then output the report to stdout.
    # Otherwise use the basename of filename, with the extension changed to '.rpt' to create the reportFile filename.
    # If reportDir is specified, then create the file as reportDir/reportFile.rpt
    # If reportDir is not specified, then create the file as inputDir/reportFile.rpt
    hl7MessageFiles = []
    if inputFile is not None:
        if inputFile == '-':
            hl7MessageFiles.append('-')
        elif inputDir is None:
            hl7MessageFiles.append(inputFile)
        else:
            hl7MessageFiles.append(os.path.join(inputDir, inputFile))
    else:
        if inputDir is None:
            hl7MessageFiles.append('-')
        else:
            for thisFile in os.listdir(inputDir):
                hl7MessageFiles.append(os.path.join(inputDir, thisFile))

    # Process each of these HL7 v2.x vertical bar encoded messages
    for messageFile in hl7MessageFiles:
        # Open the reports file
        if messageFile == '-':
            reportFile = sys.stdout
        else:
            basename = os.path.basename(messageFile)
            name, ext = os.path.splitext(basename)
            reportFilename = name + '.rpt'
            reportName = os.path.join(reportDir, reportFilename)
            try:
                reportFile = open(reportName, 'wt', encoding='utf-8', newline='')
            except:
                logger.fatal('Cannot create report file - %s', reportFilename)
                logging.shutdown()
                sys.exit(EX_CANTCREAT)

        # Get the vertical bar message
        hl7Message = getDocument(messageFile)

        # Check for MLLP
        if (hl7Message[0:1] == chr(11)) and (hl7Message[-2:] == chr(28) + chr(13)):
            hl7Message = hl7Message[1:-2]

        # Convert this HL7 v2.x vertical bar encoded message into a HL7 v2.xml XML tagged message and validate it against the HL7 v2.x XML schema
        Segments = hl7Message.rstrip().split('\r')
        SegmentStatus = [True for i in range(len(Segments))]
        SegmentFields = [ [] for i in range(len(Segments))]

        # Check that the MSH can at least be partially parsed
        MSH = Segments[0]
        if len(MSH) < 20:
            logger.fatal('First segment too short - less than 20 characters')
            logging.shutdown()
            sys.exit(EX_DATAERR)
        if MSH[0:3] != 'MSH':
            logger.fatal('First segment not MSH')
            logging.shutdown()
            sys.exit(EX_DATAERR)

        # Now partially parse the first segment (should be MSH)
        # for the field separator and encoding characters
        fieldSep = MSH[3:4]
        MSHfields = MSH.split(fieldSep)
        if len(MSHfields[1]) < 4:
            subCompSep = ''
        else:
            subCompSep = MSHfields[1][3:4]
        if len(MSHfields[1]) < 3:
            escChar = ''
            subCompSep = ''
        else:
            escChar = MSHfields[1][2:3]
            subCompSep = MSHfields[1][3:4]
        if len(MSHfields[1]) < 2:
            logger.fatal('MSH.2 field less then 2 characters long')
            logging.shutdown()
            sys.exit(EX_DATAERR)
        compSep = MSHfields[1][0:1]
        repSep = MSHfields[1][1:2]

        # And check that MSH has enough fields
        if len(MSHfields) < 12:
            logger.fatal('MSH segment too short - no version!')
            logging.shutdown()
            sys.exit(EX_DATAERR)

        # Now we can further parse the MSH segment for the message type, event and structure
        # All we really want is structure (msgStruct)
        struct = MSHfields[8]
        msgStruct = ''
        if struct == '' :
            logger.fatal('Missing MSH.9.1 component [Message Code]')
            logging.shutdown()
            sys.exit(EX_DATAERR)
        if struct == 'ACK':         # |ACK| is legal?
            msgStruct = 'ACK'
        else:
            typeParts = struct.split(compSep)
            if len(typeParts) == 1:     # |TYP| is illegal if TYP is not ACK
                logger.critical('Missing MSH.9.2 component [Trigger Event] and MSH.9.3 component [Message Structure]')
                logging.shutdown()
                sys.exit(EX_DATAERR)
            msgType = typeParts[0]
            msgTrigger = typeParts[1]
            if len(typeParts) == 3:
                msgStruct = typeParts[2]
            if msgStruct == '':           # We don't have structure, so we will have to deduce it
                if msgType == '':           # |^TRG| and |^TRG^| are illegal
                    logger.critical('Missing MSH.9.1 component [Message Type]')
                    logging.shutdown()
                    sys.exit(EX_DATAERR)
                if msgTrigger == '':
                    if msgType == 'ACK':        # |ACK^| and |ACK^^| are legal?
                        msgStruct = 'ACK'
                    else:               # |TYP^| and |TYP^^| are illegal
                        logger.critical('Missing MSH.9.2 component [Trigger Event] and MSH.9.3 component [Message Structure]')
                        logging.shutdown()
                        sys.exit(EX_DATAERR)
                else:       # Try and deduce message structure from type and trigger
                    if msgType not in hl7messageStructures:
                        logger.critical('Unknown MSH.9.1 [Message Type] (%s) not in (%s)', msgType, hl7messageStructures)
                        logging.shutdown()
                        sys.exit(EX_DATAERR)
                    if msgTrigger not in hl7messageStructures[msgType]:
                        logger.critical('Unknown MSH.9.2 [Message Trigger] (%s) not in (%s)', msgTrigger, hl7messageStructures[msgType])
                        logging.shutdown()
                        sys.exit(EX_DATAERR)
                    msgStruct = hl7messageStructures[msgType][msgTrigger]

        # Now we need to read in the message structure as defined in the xsd
        if not os.path.isfile(os.path.join(schemaDir, 'xsd', msgStruct + '.xsd')):
            logger.critical('Unknown message structure (%s)', msgStruct)
            logging.shutdown()
            sys.exit(EX_DATAERR)
        messageTree = et.parse(os.path.join(schemaDir, 'xsd', msgStruct + '.xsd'))
        messageRoot = messageTree.getroot()
        segmentList = messageRoot.find("xsd:complexType[@name='" + msgStruct + ".CONTENT']/xsd:sequence", namespaces)

        # Check that the definintion starts with MSH
        if segmentList[0].attrib['ref'] != 'MSH' :
            logger.critical('MSH not defined for messages structure(%s)', msgStruct)
            logging.shutdown()
            sys.exit(EX_CONFIG)

        # Now validate the HL7 v2.x vertical bar message
        restart = True
        while (restart):
            segmentNo = 0
            for thisSeg in segmentBusinessRules:
                for group in segmentBusinessRules[thisSeg]:
                    if (group is not None) and (group != msgStruct):
                        continue
                    for rule in segmentBusinessRules[thisSeg][group]:
                        for repeatFields in segmentBusinessRules[thisSeg][group][rule]:
                            for thisType in segmentBusinessRules[thisSeg][group][rule][repeatFields]:
                                if thisType not in ['min', 'max']:
                                    continue
                                segmentBusinessRules[thisSeg][group][rule][repeatFields][thisType]['passed'] = 0
            restart, hl7XML = validateXML(segmentList, msgStruct, [], False, False, 0)
            if restart:         # Truncate the report file by closing it and reopening
                if reportFile != sys.stdout:
                    reportFile.flush()
                    reportFile.close()
                    try:
                        reportFile = open(reportName, 'wt', encoding='utf-8', newline='')
                    except:
                        logger.fatal('Cannot create report file - %s', reportFilename)
                        logging.shutdown()
                        sys.exit(EX_CANTCREAT)

        # Test any whole of message segment rules - if any - for this message
        for thisSeg in segmentBusinessRules:
            for group in segmentBusinessRules[thisSeg]:
                if (group is not None) and (group != msgStruct):
                    continue
                for rule in segmentBusinessRules[thisSeg][group]:
                    for repeatFields in segmentBusinessRules[thisSeg][group][rule]:
                        for thisType in segmentBusinessRules[thisSeg][group][rule][repeatFields]:
                            if thisType not in ["min", "max"]:
                                continue
                            passed = segmentBusinessRules[thisSeg][group][rule][repeatFields][thisType]['passed']
                            count = segmentBusinessRules[thisSeg][group][rule][repeatFields][thisType]['count']
                            if ((thisType == "min") and (passed < count)) or ((thisType == "max") and (passed > count)):
                                comment = f'Failed Segment Business Rule ({thisSeg}:{group}:{rule}:{repeatFields}:{thisType}:{count} - passed {passed})'
                                print(comment, file=reportFile)
                                hl7XML.append(et.Comment(comment))
                    
        # Now run the XPath Buisness Rules
        for rule in XPathBusinessRules:         # test each rule in the XPathBusinessRules
            for rulePath in XPathBusinessRules[rule]:
                try:
                    ruleNodes = hl7XML.xpath(rulePath)          # Fetch the rule nodes from the hl7XML message
                except Exception as e:
                    comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}) Testing failure - {e}'
                    print(comment, file=reportFile)
                    hl7XML.append(et.Comment(comment))
                    continue
                if len(ruleNodes) == 0:
                    continue                                    # No matching data in this message to be tested for this rulePath, so skip to the next rulePath
                for ruleNode in ruleNodes:
                    if ruleNode.tag is et.Comment:
                        continue
                    if (not ruleNode.tag.startswith(msgStruct)) and (not len(ruleNode.tag) == 3):        # ruleNode must be a segment group or a segment
                        comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}) Testing failure - rulePath must return a segment group or a segment'
                        print(comment, file=reportFile)
                        hl7XML.append(et.Comment(comment))
                        continue
                    for ruleType in XPathBusinessRules[rule][rulePath]:     # For each rule/rulePath/ruleType combination
                        ruleCount = XPathBusinessRules[rule][rulePath][ruleType]['ruleCount']
                        for fieldPath in XPathBusinessRules[rule][rulePath][ruleType]['fields']:
                            try:
                                if not fieldPath.startswith('//'):       # Relative addressing
                                    fieldNodes = ruleNode.xpath(fieldPath)
                                else:                               # Absolute addressing
                                    fieldNodes = hl7XML.xpath(fieldPath)
                            except Exception as e:
                                comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}:fieldPath {fieldPath}) Testing failure - {e}'
                                print(comment, file=reportFile)
                                hl7XML.append(et.Comment(comment))
                                continue
                            if len(fieldNodes) == 0:
                                continue                                    # No matching data in this message to be tested for this fieldPath, so skip to the next fieldPath
                            for fieldType in XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath]:
                                for linked in XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType]:
                                    for repNo, fieldNode in enumerate(fieldNodes):
                                        if fieldNode.tag is et.Comment:
                                            continue
                                        parent = fieldNode.getparent()
                                        if (parent is None) or (len(parent.tag) != 3) or (not fieldNode.tag.startswith(parent.tag)):        # fieldNode must be a child a segment group or a segment
                                            comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}:fieldPath {fieldPath}) Testing failure - fieldPath must return a field'
                                            print(comment, file=reportFile)
                                            hl7XML.append(et.Comment(comment))
                                            continue
                                        fieldCount = XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType][linked]['fieldCount']
                                        data = {}
                                        xpaths = XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType][linked]['XPaths']
                                        data = getFieldData(data, fieldNode, xpaths, linked, repNo, rule, rulePath, ruleType)
                                        # Now run the rules engine for this rule/rulePath/ruleType/fieldPath/fieldType/linked combination
                                        data['Rule'] = rule
                                        data['Repeat Number'] = repNo + 1
                                        logger.debug(f'Checking Business XPath Rule({rule}) with data {data}', extra={'raw_message':True})
                                        (status, newData) = rulesEngine.decide(data)
                                        if 'errors' in status:
                                            logger.critical('ERROR: Critical Error(s) in Rules Definitions in XPath Business Rules for rule (%s)', rule)
                                            for thisError in status['errors']:
                                                logger.critical('ERROR: %s', thisError)
                                            logging.shutdown()
                                            sys.exit(EX_CONFIG)
                                        if isinstance(newData, list):
                                            if len(newData) == 0:
                                                logger.critical('ERROR: Critical Error in Rules Definitions in XPath Business Rules for rule (%s) - no Decision Table executed', rule)
                                                logging.shutdown()
                                                sys.exit(EX_CONFIG)
                                            Result = newData[-1]['Result']
                                        else:
                                            Result = newData['Result']
                                        if not linked:
                                            if Result['Passed'] == False:
                                                comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}:fieldPath {fieldPath}:fieldType {fieldType}:linked {linked}) Testing failure'
                                                print(comment, file=reportFile)
                                                hl7XML.append(et.Comment(comment))
                                        else:
                                            if Result['Passed'] == True:
                                                fieldCount -= 1
                                                ruleCount -= 1
                                        if fieldType in ['min', 'max']:
                                            noPassed = XPathBusinessRules[rule][rulePath][ruleType]['fields'][fieldPath][fieldType][linked]['fieldCount'] - fieldCount
                                            if (fieldType == 'min') and (fieldCount > 0):
                                                comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}:fieldPath {fieldPath}:fieldType {fieldType}) Testing failure - {noPassed:d} field(s) passed'
                                                print(comment, file=reportFile)
                                                hl7XML.append(et.Comment(comment))
                                            if (fieldType == 'max') and (fieldCount < 0):
                                                comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}:fieldPath {fieldPath}:fieldType {fieldType}) Testing failure - {noPassed:d} field(s) passed'
                                                print(comment, file=reportFile)
                                                hl7XML.append(et.Comment(comment))
                        if ruleType in ['min', 'max']:
                            noPassed = XPathBusinessRules[rule][rulePath][ruleType]['ruleCount'] - ruleCount
                            if (ruleType == 'min') and (fieldCount > 0):
                                comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}) Testing failure - {noPassed:d} rule(s) passed'
                                print(comment, file=reportFile)
                                hl7XML.append(et.Comment(comment))
                            if (ruleType == 'max') and (ruleCount < 0):
                                comment = f'ERROR: XPath Business Rule (rule {rule}:rulePath {rulePath}:ruleType {ruleType}) Testing failure - {noPassed:d} rule(s) passed'
                                print(comment, file=reportFile)
                                hl7XML.append(et.Comment(comment))

        # Save the HL7 V2.xml message
        hl7XML.set('xmlns', 'urn:hl7-org:v2xml')
        hl7XML.set(et.QName('http://www.w3.org/2001/XMLSchema-instance', 'schemaLocation'), f'urn:hl7-org:v2:qxml {msgStruct}.xsd')
        et.indent(hl7XML, '    ')
        s = et.tostring(hl7XML, encoding='unicode')
        s = hl7charRef.sub(r'&\1', s)
        if messageFile == '-':
            print(s)
        else:
            logger.info(s, extra={'raw_message':True})
            basename = os.path.basename(messageFile)
            name, ext = os.path.splitext(basename)
            outputFile = name + '.xml'
            outputFile = os.path.join(outputDir, outputFile)
            with open(outputFile, 'wt', encoding='utf-8', newline='') as fpout:
                print(s, file=fpout)
