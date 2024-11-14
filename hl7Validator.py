# pylint: disable=line-too-long
'''
Script hl7Validator.py
A script to validate an HL7 v2.x vertical bar message with respect to it's equivalient HL7 v2.xml XML schema.
THis script also outputs the equivalent HL7 v2.xml XML tagged message.


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
    The name of the HL7 vertical bar message file to be converted.

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
import csv
from xml.etree import ElementTree as et

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
segmentNo = 0           # The next segment in the message to be converted
segmentRoot = None      # The XML Schema for the segments
fieldRoot = None        # The XML Schema for the fields
dataTypeRoot = None     # The XML Schema for the data types
messageRoot = None      # The XML Schema for the message being converted
namespaces = None       # The namespaces of the XML Schemas
fieldSep = None         # The field separator character
repSep = None           # The repeat separator
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
msgStruct = None
reportFile = None       # The report file
hl7Tables = None        # The HL7 and User tables
fieldLengths = None     # The maximum length of any field
datatypeLengths = None  # The maxiumum lenght of an datatype component
valueSets = None        # The value sets for CE, CF, CNE and CWE coded elements



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
        logging.fatal('No file named %s', fileName)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    with open(fileName, 'rt', encoding='utf-8') as fpin:
        for line in fpin:
            thisHL7message += line.rstrip() + '\r'
        return thisHL7message


def validateXML(sequenceList, tag, optional, isChoice, depth):
    '''
    Output an XML structure for all the elements in the sequence list where we have a matching segment in the Segments.
    If there is no matching segment then report a validation error and output the segment as an XML comment.
    PARAMETERS:
        xmlElement - et.Element, the current element we are working on
        sequenceList - et.Element,the XML sequence we are working on, from the message structure XSD
        sequenceAt - int, how far we are through this sequence list
        tag - str, the group tag, if any
        optional - boolean whether no output is valid
        depth - int, the recursion depth
    This is a recursive routine, so we use depth to prevent indifinite recurrsion
    '''

    global segmentNo

    if depth > 200:
        # Treat this segment as unexpected
        comment= f'Unexpected Segment at {segmentNo + 1:d} - "{Segments[segmentNo]}"'
        print(comment, file=reportFile)
        newElement = et.Element(tag)
        newElement.append(et.Comment(comment))
        segmentNo += 1
        return newElement
    depth += 1
    sequenceAt = 0
    thisElement = None
    tagged = False
    occurs = 0
    lastSeg = None
    while sequenceAt < len(sequenceList):           # Check the next segment
        if 'ref' not in sequenceList[sequenceAt].attrib:
            logging.critical('XML Schema definition is missing "ref" for segment at %d in message struct %s', sequenceAt, msgStruct)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        if sequenceList[sequenceAt].attrib['ref'] != Segments[segmentNo][0:3]:
            # Check if this segment is here, after some optional segments
            if len(sequenceList[sequenceAt].attrib['ref']) > 3:     # A group
                groupRef = sequenceList[sequenceAt].attrib['ref']
                groupOptional = False
                if 'minOccurs' not in sequenceList[sequenceAt]:
                    logging.critical('XML Schema definition is missing "minOccurs" at %d in message struct %s', sequenceAt, msgStruct)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
                if sequenceList[sequenceAt].attrib['minOccurs'] == '0':
                    groupOptional = True
                thisChoice = False
                groupList = messageRoot.find("xsd:complexType[@name='" + groupRef + ".CONTENT']/xsd:sequence", namespaces)
                if groupList is None:
                    groupList = messageRoot.find("xsd:complexType[@name='" + groupRef + ".CONTENT']/xsd:choice", namespaces)
                    thisChoice = True
                    if groupList is None:
                        logging.critical('XML Schema definition missing either xsd:sequence or xsd:choice for %s', groupRef + '.CONTENT')
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                groupXML = validateXML(groupList, groupRef, groupOptional, thisChoice, depth)           # Validate this group of segments
                if groupXML is not None:        # At least one segment was found at in this group
                    if not tagged:
                        thisElement = et.Element(tag)
                        tagged = True
                    thisElement.append(groupXML)
                    if segmentNo < len(Segments):       # More to do
                        continue
                    return thisElement
                # Nothing found - make sure group is optional and skip if it is
                if sequenceList[sequenceAt].attrib['minOccurs'] == '0':
                    sequenceAt += 1
                    continue
                return thisElement
            # Check if this segment is optional
            if sequenceList[sequenceAt].attrib['minOccurs'] == '0':
                sequenceAt += 1
                continue
            # This is some sort of failure something, that is this segment isrequire and is not present
            # If this sequence is optional, then return what we have
            if optional:
                return thisElement
            # Otherwise, treat this segment as 'unexpected'
            comment= f'Unexpected Segment at {segmentNo + 1:d}: "{Segments[segmentNo]}"'
            print(comment, file=reportFile)
            if not tagged:
                thisElement = et.Element(tag)
                tagged = True
            thisElement.append(et.Comment(comment))
            segmentNo += 1
            if segmentNo < len(Segments):
                continue
            return thisElement
        # A matching segment
        seg = Segments[segmentNo][0:3]
        if (lastSeg is None) or (lastSeg != seg):
            lastSeg = seg
            occurs = 0
        if not tagged:
            thisElement = et.Element(tag)
            tagged = True
        segElement = et.Element(seg)
        Fields = Segments[segmentNo].split(fieldSep)            # Split this segment into fields
        if Fields[0] == 'MSH':
            Fields.insert(1, fieldSep)
        seg = Fields[0]
        Fields = Fields[1:]
        xmlSeg = segmentRoot.find("xsd:complexType[@name='" + seg + ".CONTENT']/xsd:sequence", namespaces)
        if xmlSeg is None:
            logging.critical('XML Schema is missing segment definition for segment %s', seg)
            logging.shutdown()
            sys.exit(EX_CONFIG)
        for i, field in enumerate(Fields):          # Process each field
            fieldCode = f'{seg}-{i + 1:d}'
            if (i < len(xmlSeg)) and ('ref' in xmlSeg[i].attrib) and ('minOccurs' in xmlSeg[i].attrib) and ('maxOccurs' in xmlSeg[i].attrib):
                fieldRef = xmlSeg[i].attrib['ref']
                thisMin = xmlSeg[i].attrib['minOccurs']
                try:
                    fieldMin = int(fieldMin)
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
                thisType = fieldRoot.find("xsd:attributeGroup[@name='" + fieldRef + ".ATTRIBUTES']/xsd:attribute[@name='Type']", namespaces)
                if (thisType is not None) and ('fixed' in thisType.attrib):
                    fieldType = thisType.attrib['fixed']
                else:
                    fieldType = None                    
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
            if field == '':
                if (fieldMin is not None) and (fieldMin > 0):
                    comment = f'Missing required field [{fieldCode}] in Segment {seg} at segment {segmentNo + 1:d}'
                    print(comment, file=reportFile)
                    fieldXML.append(et.Comment(comment))
                    segElement.append(fieldXML)
                continue
            if (seg == 'MSH') and (i == 1):         # Split this field into repetitions - except the encoding characters and FT data
                fieldReps = [field]
            elif fieldType == 'FT':
                fieldReps = [field]
            else:
                fieldReps = field.split(repSep)
            for j, thisField in enumerate(fieldReps):
                if thisField == '""':
                    continue
                if (fieldMax is not None) and (fieldMax <= j):
                    comment = f'Unexpected field repeat [{j + 1}] in segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}]'
                    print(comment, file=reportFile)
                    fieldXML.append(et.Comment(comment))
                if fieldRef is not None:
                    if fieldType is None:
                        comment = f'Undefined Field in Segment {seg} at {segmentNo:%d}, field {fieldCode}'
                        print(comment, file=reportFile)
                        fieldXML.append(et.Comment(comment))
                        fieldXML.text = thisField
                        comment = fixElement(fieldXML, 'ST', None, None, None)
                        if comment is not None:
                            comment += f' in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}]'
                            print(comment, file=reportFile)
                            fieldXML.append(et.Comment(comment))
                        segElement.append(fieldXML)
                        continue
                    if fieldType == 'varies':
                        if (seg == 'OBX') and (fieldRef == 'OBX.5'):
                            fieldType = Fields[1]
                        elif (seg == 'MFE') and (fieldRef == 'MFE.4') and (len(Fields) > 4):
                            fieldType = Fields[4]
                    dataTypeBits = dataTypeRoot.find("xsd:complexType[@name='" + fieldType + "']/xsd:sequence", namespaces)
                    if fieldType == 'FT':       # FT has a sequence, but not components
                        dataTypeBits = None
                    if dataTypeBits is not None:
                        Components = thisField.split(compSep)
                        for k, component in enumerate(Components):
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
                                    comment = f'Missing required component [{componentCode}] in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repeat {j + 1:d}'
                                    print(comment, file=reportFile)
                                    componentXML.append(et.Comment(comment))
                                    fieldXML.append(componentXML)
                                continue
                            if componentRef is not None:
                                if componentType is None:
                                    comment = f'Undefined component in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {j + 1:d}, component [{componentCode}]'
                                    print(comment, file=reportFile)
                                    componentXML.append(et.Comment(comment))
                                    componentXML.text = component
                                    comment = fixElement(componentXML, 'ST', fieldType, k + 1, fieldXML)
                                    if comment is not None:
                                        comment += f' in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {j+ 1:d}, component [{componentCode}]'
                                        print(comment, file=reportFile)
                                        componentXML.append(et.Comment(comment))
                                    fieldXML.append(componentXML)
                                    continue
                                componentBits = dataTypeRoot.find("xsd:complexType[@name='" + componentType + "']/xsd:sequence", namespaces)
                                componentXML = et.Element(componentRef)
                                if (componentBits is not None) and (subCompSep != '') and (componentCode != 'OBX.3.1'):
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
                                                comment = f'Missing required subcomponent [{subCompCode}] in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {j + 1:d}, subcomponent [{subCompCode}]'
                                                print(comment, file=reportFile)
                                                subComponentXML.append(et.Comment(comment))
                                                componentXML.append(subComponentXML)
                                            continue
                                        if subCompRef is not None:
                                            if subCompType is None:
                                                comment = f'Undefined subcomponent in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {j + 1:d}, subcomponent [{subCompCode}]'
                                                print(comment, file=reportFile)
                                                subComponentXML.append(et.Comment(comment))
                                        else:
                                            comment = f'Unexpected subcomponent in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {j + 1:d}, subcomponent [{subCompCode}] - {subComponent}'
                                            print(comment, file=reportFile)
                                            subComponentXML.append(et.Comment(comment))
                                        subComponentXML.text = subComponent
                                        comment = fixElement(subComponentXML, subCompType, componentType, l + 1, componentXML)
                                        if comment is not None:
                                            comment += f' in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {j+ 1:d}, subcomponent [{subCompCode}]'
                                            print(comment, file=reportFile)
                                            subComponentXML.append(et.Comment(comment))
                                        if (subCompTable is not None) and (hl7Tables is not None) and (subCompTable in hl7Tables):
                                            if subComponent not in hl7Tables[fieldTable]['codes']:
                                                comment = f'Illegal value "{subComponent}" - not in {hl7Tables[subCompTable]['type']} table {subCompTable} in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {j + 1:d}, subcomponent [{subCompCode}]'
                                                print(comment, reportFile)
                                                subComponentXML.append(et.Comment(comment))
                                        if (datatypeLengths is not None) and (subCompType in datatypeLengths) and (l in datatypeLengths[subCompType]):
                                            if len(subComponent) > datatypeLengths[subCompType][l]:
                                                comment = f'Illegally long subcomponent - "{subComponent}" in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {j + 1:d}, subComponent [{subCompCode}]'
                                                print(comment, file=reportFile)
                                                subComponentXML.append(et.Comment(comment))
                                        if (valueSets is not None) and (l in [2, 5]) and (componentCode in valueSets) and (subComponent in valueSets[componentCode]):
                                            if (subComponents[l -2] not in valueSets[componentCode][subComponent]):
                                                comment = f'Identifier "{subComponents[l - 2]}" not in coding system "{subComponent}" in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {j + 1:d}, component[{componentCode}]'
                                                print(comment, file=reportFile)
                                                subComponentXML.append(et.Comment(comment))
                                        componentXML.append(subComponentXML)
                                else:
                                    componentXML.text = component
                                    comment = fixElement(componentXML, componentType, fieldType, i + 1, fieldXML)
                                    if comment is not None:
                                        comment += f' in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {k + 1:d}, component [{componentCode}]'
                                        print(comment, file=reportFile)
                                        componentXML.append(et.Comment(comment))
                                    if (componentTable is not None) and (hl7Tables is not None) and (componentTable in hl7Tables):
                                        if component not in hl7Tables[fieldTable]['codes']:
                                            comment = f'Illegal value "{component}" - not in {hl7Tables[componentTable]['type']} table {componentTable} in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {k + 1:d}, component [{componentCode}]'
                                            print(comment, reportFile)
                                            componentXML.append(et.Comment(comment))
                                    if (datatypeLengths is not None) and (componentType in datatypeLengths) and (k in datatypeLengths[componentType]):
                                        if len(component) > datatypeLengths[componentType][k]:
                                            comment = f'Illegally long component - "{component}" in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {j + 1:d}, component [{componentCode}]'
                                            print(comment, file=reportFile)
                                            componentXML.append(et.Comment(comment))
                                    if (valueSets is not None) and (k in [2, 5]) and (fieldCode in valueSets) and (component in valueSets[fieldCode]):
                                        if (Components[k -2] not in valueSets[componentCode][component]):
                                            comment = f'Identifier "{Components[l - 2]}" not in coding system "{component}" in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {j + 1:d}'
                                            print(comment, file=reportFile)
                                            componentXML.append(et.Comment(comment))
                            else:
                                comment = f'Unexpected component in Segment {seg} at segment {segmentNo + 1:d}, field {fieldCode}, repetition {k + 1:d} - {component}'
                                print(comment, file=reportFile)
                                fieldXML.append(et.Comment(comment))
                                componentXML.text = component
                                comment = fixElement(componentXML, componentType, fieldType, i + 1, fieldXML)
                                if comment is not None:
                                    comment += f' in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {k + 1:d}, component [{componentCode}]'
                                    print(comment, file=reportFile)
                                    componentXML.append(et.Comment(comment))
                        fieldXML.append(componentXML)
                    else:
                        fieldXML.text = thisField
                        comment = fixElement(fieldXML, fieldType, None, None, None)
                        if comment is not None:
                            comment += f' in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {k + 1:d}'
                            print(comment, file=reportFile)
                            fieldXML.append(et.COmment(comment))
                        if (fieldTable is not None) and (hl7Tables is not None) and (fieldTable in hl7Tables):
                            if thisField not in hl7Tables[fieldTable]['codes']:
                                comment = f'Illegal value "{thisField}" - not in {hl7Tables[fieldTable]['type']} table {fieldTable} in Segment {seg} at segment {segmentNo + 1:d}, field [{fieldCode}], repetition {k + 1:d}'
                                print(comment, reportFile)
                                fieldXML.append(et.Comment(comment))
                        if (fieldLengths is not None) and (fieldCode in fieldLengths) and (fieldLengths[fieldCode] not in [999999, 65356]):
                            if len(thisField) > fieldLengths[fieldCode]:
                                comment = f'Illegally long field - "{thisField}" in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}], repetition {j + 1:d}'
                                print(comment, file=reportFile)
                                fieldXML.append(et.Comment(comment))
                else:       # Undefined field
                    comment = f'Unexpected field in Segment {seg} at {segmentNo + 1:d}, field {fieldCode} - {thisField}'
                    print(comment, file=reportFile)
                    fieldXML.append(et.Comment(comment))
                    fieldXML.text = thisField
                    comment = fixElement(fieldXML, fieldType, None, None, None)
                    if comment is not None:
                        comment += f' in Segment {seg} at segment {segmentNo + 1:d} in field [{fieldCode}]'
                        print(comment, file=reportFile)
                        fieldXML.append(et.Comment(comment))
                segElement.append(fieldXML)
        thisElement.append(segElement)
        segmentNo += 1
        if segmentNo == len(Segments):
            return thisElement
        if isChoice:
            return thisElement
        occurs += 1
        maxOccurs = sequenceList[sequenceAt].attrib['maxOccurs']
        if maxOccurs == 'unbounded':
            continue
        if int(occurs) < int(maxOccurs):
            continue
        sequenceAt += 1
        if sequenceAt < len(sequenceList):
            continue
    return thisElement


def fixElement(thisElement, textType, parentType, parentSequence, parentXML):
    '''
    Fix the text associated with thisElement
    '''
    elementText = thisElement.text

    # Check for deleted data
    if elementText == '""':
        return None
    # Check for missing data
    if elementText == '':
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
            return 'Illegally formatted telephone number "{elementText}"'
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
            return 'Illegally formatted telephone number "{elementText}"'
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


if __name__ == '__main__':
    '''
    The main code
    Start by parsing the command line arguements and setting up logging.
    Then process each file name in the command line - read the HL7 v2.x vertical bar message
    and convert it an HL7 v2.xml XML tagged message
    '''

    # Set the command line options
    progName = sys.argv[0]
    progName = progName[0:-3]        # Strip off the .py ending
    parser = argparse.ArgumentParser(description='hl7Validator')
    parser.add_argument('-I', '--inputDir', dest='inputDir',
                        help='The folder containing the HL7 v2.x vertical bar encoded message files')
    parser.add_argument('-i', '--inputFile', dest='inputFile',
                        help='The name of the HL7 v2.x vertical bar encoded message file')
    parser.add_argument ('-R', '--reportDir', dest='reportDir', default='.', metavar='reportDir',
                         help='The name of the directory where the report(s) file will be created')
    parser.add_argument('-O', '--outputDir', dest='outputDir', default='.',
                        help='The folder where the HL7 v2.xml XML tagged message(s) will be created (default=".")')
    parser.add_argument('-S', '--schemaDir', dest='schemaDir', required=True, default='schema/v2.4',
                        help='The folder containing the HL7 v2.xml XML schema files (default="schema/v2.4")')
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

    # Check that the schemaDir folder exist and read in the segment, fields and datatype schema
    if not os.path.isdir(schemaDir):
        logging.critical('No schemaDir folder named "%s"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if not os.path.isdir(os.path.join(schemaDir, 'xsd')):
        logging.critical('No schemaDir folder named "%s/xsd"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if not os.path.isfile(os.path.join(schemaDir, 'xsd', 'segments.xsd')):
        logging.critical('No file "segments.xsd" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    segmentTree = et.parse(os.path.join(schemaDir, 'xsd', 'segments.xsd'))
    segmentRoot = segmentTree.getroot()
    if not os.path.isfile(os.path.join(schemaDir, 'xsd', 'fields.xsd')):
        logging.critical('No file "fields.xsd" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    fieldTree = et.parse(os.path.join(schemaDir, 'xsd', 'fields.xsd'))
    fieldRoot = fieldTree.getroot()
    if not os.path.isfile(os.path.join(schemaDir, 'xsd', 'datatypes.xsd')):
        logging.critical('No file "datatypes.xsd" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    dataTypeTree = et.parse(os.path.join(schemaDir, 'xsd', 'datatypes.xsd'))
    dataTypeRoot = dataTypeTree.getroot()
    namespaces={'xsd':'http://www.w3.org/2001/XMLSchema'}

    # Check that the message structures file exists
    if not os.path.isfile(os.path.join(schemaDir, 'hl7Table0354.csv')):
        logging.critical('No file "hl7Table054.csv" in schemaDir folder(%s/xsd)', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    hl7messageStructures = {}
    with open(os.path.join(schemaDir, 'hl7Table0354.csv'), 'rt', encoding='utf-8') as hl7TableFile:
        csvReader = csv.reader(hl7TableFile, delimiter='\t')
        header = True
        for row in csvReader:
            if header:
                header = False
                continue
            msgStructure = row[0]
            msgStruct = msgStructure[0:3]
            if msgStruct not in hl7messageStructures:
                hl7messageStructures[msgStruct] = {}
            msgTriggers = row[1].split(',')
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

    # Check that HL7 and User tables file exists
    if os.path.isfile(os.path.join(schemaDir, 'hl7Tables.csv')):
        hl7Tables = {}
        with open(os.path.join(schemaDir, 'hl7Tables.csv'), 'rt', encoding='utf-8') as hl7TableFile:
            csvReader = csv.reader(hl7TableFile, delimiter='\t')
            header = True
            tableType = None
            tableNumber = None
            for row in csvReader:
                if header:
                    header = False
                    continue
                if (len(row) > 0) and (row[0] != ''):
                    tableType = row[0]
                if (len(row) > 1) and (row[1] != ''):
                    tableNumber = row[1]
                    if tableNumber not in hl7Tables:
                        if tableType is None:
                            logging.critical('Error in hl7Tables.csv file - table [%s] without table type', tableNumber)
                            logging.shutdown()
                            sys.exit(EX_CONFIG)
                        hl7Tables[tableNumber] = {}
                        hl7Tables[tableNumber]['type'] = tableType
                        hl7Tables[tableNumber]['codes'] = []
                if len(row) < 4:
                    continue
                tableCode = row[3]
                if tableCode == '':
                    continue
                if tableNumber is None:
                    logging.critical('Error in hl7Tables.csv file - table code [%s] without table number', tableCode)
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
                hl7Tables[tableNumber]['codes'].append(tableCode)

    # Check if field length file exits
    if os.path.isfile(os.path.join(schemaDir, 'hl7Fields.csv')):
        fieldLengths = {}
        with open(os.path.join(schemaDir, 'hl7Fields.csv'), 'rt', encoding='utf-8') as hl7FieldsFile:
            csvReader = csv.reader(hl7FieldsFile, delimiter='\t')
            header = True
            for row in csvReader:
                if header:
                    header = False
                    continue
                if len(row) < 3:
                    logging.critical('Error in hl7Fields.csv - too few columns')
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
                elif len(row) == 3:
                    seg = row[0]
                    field = row[1]
                    try:
                        length = int(row[2])
                    except:
                        logging.critical('Error in hl7Fields.csv - illegal length [%s]', row[2])
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                    fieldCode = seg + '-' + field
                    fieldLengths[fieldCode] = length
                else:
                    logging.critical('Error in hl7Fields.csv - too many columns - "%s"', str(row))
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
    
    # Check if the datatype lengths file exists
    if os.path.isfile(os.path.join(schemaDir, 'hl7DataTypes.csv')):
        datatypeLengths = {}
        with open(os.path.join(schemaDir, 'hl7DataTypes.csv'), 'rt', encoding='utf-8') as hl7DataTypesFile:
            csvReader = csv.reader(hl7DataTypesFile, delimiter='\t')
            header = True
            dataType = None
            for row in csvReader:
                if header:
                    header = False
                    continue
                if len(row) < 1:
                    continue
                elif len(row) == 1:
                    dataType = row[0]
                    if dataType not in datatypeLengths:
                        datatypeLengths[dataType] = {}
                    continue
                elif len(row) == 2:
                    try:
                        seq = int(row[0]) - 1
                        length = int[row[1]]
                    except:
                        logging.critical('Error in hl7DataTypes.csv - invalid sequence [%s] or length [%s]', row[0], row[1])
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                    if dataType is None:
                        logging.critial('Error in hl7DataTypes.csv - missing dataType at start of file')
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                    datatypeLengths[dataType][seq] = length
                else:
                    logging.critical('Error in hl7DataTypes.csv - too many columns - "%s"', str(row))
                    logging.shutdown()
                    sys.exit(EX_CONFIG)

    # Check if we have a ValueSets file
    if os.path.isfile(os.path.join(schemaDir, 'valueSets.csv')):
        valueSets = {}
        with open(os.path.join(schemaDir, 'valueSets.csv'), 'rt', encoding='utf-8') as valueSetsFile:
            csvReader = csv.reader(valueSetsFile, delimiter='\t')
            header = True
            fieldOrComponent = None
            codingSystem = None
            for row in csvReader:
                if header:
                    header = False
                    continue
                if len(row) < 1:
                    continue
                if len(row) == 1:
                    fieldOrComponent = row[0]
                    continue
                elif len(row) == 2:
                    if row[0] != '':
                        fieldOrComponent = row[0]
                    codingSystem = row[1]
                elif len(row) == 3:
                    if row[0] != '':
                        fieldOrComponent = row[0]
                    if row[1] != '':
                        codingSystem = row[1]
                    identifier = row[2]
                    if fieldOrComponent is None:
                        logging.critical('Error in valueSets.csv - missing field or component at start of file')
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                    if codingSystem is None:
                        logging.critical('Error in valueSets.csv - missing coding system at start of file')
                        logging.shutdown()
                        sys.exit(EX_CONFIG)
                    if fieldOrComponent not in valueSets:
                        valueSets[fieldOrComponent] = {}
                    if codingSystem not in valueSets[fieldOrComponent]:
                        valueSets[fieldOrComponent][codingSystem] = []
                    valueSets[fieldOrComponent][codingSystem].append(identifier)
                else:
                    logging.critical('Error in valueSets.csv - too many columns - "%s"', str(row))
                    logging.shutdown()
                    sys.exit(EX_CONFIG)
                    
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
            if reportDir is not None:
                reportName = os.path.join(reportDir, reportFilename)
            elif inputDir is not None:
                reportName = os.path.join(inputDir, reportFilename)
            if reportName == messageFile:
                reportName = 'report_' + reportFile
            try:
                reportFile = open(reportName, 'wt', encoding='utf-8', newline='')
            except:
                logging.fatal('Cannot create report file - %s', reportFilename)
                logging.shutdown()
                sys.exit(EX_CANTCREAT)

        # Get the vertical bar message
        hl7Message = getDocument(messageFile)

        # Check for MLLP
        if (hl7Message[0:1] == chr(11)) and (hl7Message[-2:] == chr(28) + chr(13)):
            hl7Message = hl7Message[1:-2]

        # Convert this hl7 v2.x vertical bar encoded message
        Segments = hl7Message.rstrip().split('\r')

        # Check that the MSH can at least be partially parsed
        MSH = Segments[0]
        if len(MSH) < 20:
            logging.fatal('First segment too short - less than 20 characters')
            logging.shutdown()
            sys.exit(EX_DATAERR)
        if MSH[0:3] != 'MSH':
            logging.fatal('First segment not MSH')
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
            logging.fatal('MSH.2 field less then 2 characters long')
            logging.shutdown()
            sys.exit(EX_DATAERR)
        compSep = MSHfields[1][0:1]
        repSep = MSHfields[1][1:2]

        # And check that MSH has enough fields
        if len(MSHfields) < 12:
            logging.fatal('MSH segment too short - no version!')
            logging.shutdown()
            sys.exit(EX_DATAERR)

        # Now we can further parse the MSH segment for the message type, event and structure
        # All we really want is structure (msgStruct)
        struct = MSHfields[8]
        msgStruct = ''
        if struct == '' :
            logging.fatal('Missing MSH.9.1 component [Message Code]')
            logging.shutdown()
            sys.exit(EX_DATAERR)
        if struct == 'ACK':         # |ACK| is legal?
            msgStruct = 'ACK'
        else:
            typeParts = struct.split(compSep)
            if len(typeParts) == 1:     # |TYP| is illegal if TYP is not ACK
                logging.critical('Missing MSH.9.2 component [Trigger Event] and MSH.9.3 component [Message Structure]')
                logging.shutdown()
                sys.exit(EX_DATAERR)
            msgType = typeParts[0]
            msgTrigger = typeParts[1]
            if len(typeParts) == 3:
                msgStruct = typeParts[2]
            if msgStruct == '':           # We don't have structure, so we will have to deduce it
                if msgType == '':           # |^TRG| and |^TRG^| are illegal
                    logging.critical('Missing MSH.9.1 component [Message Type]')
                    logging.shutdown()
                    sys.exit(EX_DATAERR)
                if msgTrigger == '':
                    if msgType == 'ACK':        # |ACK^| and |ACK^^| are legal?
                        msgStruct = 'ACK'
                    else:               # |TYP^| and |TYP^^| are illegal
                        logging.critical('Missing MSH.9.2 component [Trigger Event] and MSH.9.3 component [Message Structure]')
                        logging.shutdown()
                        sys.exit(EX_DATAERR)
                else:       # Try and deduce message structure from type and trigger
                    print(hl7messageStructures)
                    if msgType not in hl7messageStructures:
                        logging.critical('Unknown MSH.9.1 [Message Type] (%s)', msgType)
                        logging.shutdown()
                        sys.exit(EX_DATAERR)
                    if msgTrigger not in hl7messageStructures[msgType]:
                        logging.critical('Unknown MSH.9.2 [Message Trigger] (%s)', msgTrigger)
                        logging.shutdown()
                        sys.exit(EX_DATAERR)
                    msgStruct = hl7messageStructures[msgType][msgTrigger]

        # Now we need to read in the message structure as defined in the xsd
        if not os.path.isfile(os.path.join(schemaDir, 'xsd', msgStruct + '.xsd')):
            logging.critical('Unknown message structure (%s)', msgStruct)
            logging.shutdown()
            sys.exit(EX_DATAERR)
        messageTree = et.parse(os.path.join(schemaDir, 'xsd', msgStruct + '.xsd'))
        messageRoot = messageTree.getroot()
        segmentList = messageRoot.find("xsd:complexType[@name='" + msgStruct + ".CONTENT']/xsd:sequence", namespaces)

        # Check that the definintion starts with MSH
        if segmentList[0].attrib['ref'] != 'MSH' :
            logging.critical('MSH not defined for messages structure(%s)', msgStruct)
            logging.shutdown()
            sys.exit(EX_CONFIG)

        # Now validate the HL7 v2.x vertical bar message
        segmentNo = 0
        hl7XML = validateXML(segmentList, msgStruct, False, False, 0)

        # Save the HL7 V2.xml message
        hl7XML.attrib['xmlns'] = 'urn:hl7-org:v2xml'
        hl7XML.attrib['xmlns:xsi'] = 'http://www.w3.org/2001/XMLSchema-instance'
        hl7XML.attrib['xsi:schemaLocation'] = 'urn:hl7-org:v2xml ' + msgStruct + '.xsd'
        et.indent(hl7XML, '    ')
        s = et.tostring(hl7XML, encoding='unicode')
        s = hl7charRef.sub(r'&\1', s)
        if messageFile == '-':
            print(s)
        else:
            logging.info(s)
            basename = os.path.basename(messageFile)
            name, ext = os.path.splitext(basename)
            outputFile = name + '.xml'
            if outputDir is not None:
                outputFile = os.path.join(outputDir, outputFile)
            elif outputFile == messageFile:
                outputFile = 'XML_' + outputFile
            with open(outputFile, 'wt', encoding='utf-8', newline='') as fpout:
                print(s, file=fpout)
