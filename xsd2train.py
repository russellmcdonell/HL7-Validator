# pylint: disable=line-too-long
'''
Script xsd2train.py
A script to render an HL7 v2.xml XML schema as a train diagram and output it to a '.png' file

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
    -m messageStructure|--messageStructure=messageStructure
    The name of the HL7 v2.xml message structure definition file to be rendered.

    OPTIONS
    -S schemaDir|--schemaDir=schemaDir
    The folder containing the HL7 v2.xml XML Schema files for the relevant version of HL7 v2.x
    (default = 'schema/v2.4')

    -O outputDir|--outputDir=outputDir
    The folder where the rendered '.png' file will be saved (messageStructure.png).

    -o outputFilename|--outputFilename=outputFilename
    The name of the '.png' file containing the train diagram to be created (default = 'messageStructure.png')

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
from xml.etree import ElementTree as et
import matplotlib.pyplot as plt

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

namespaces={'xsd':'http://www.w3.org/2001/XMLSchema'}   # The namespaces in the XSD message structure definition
messageRoot = None      # The root of the XSD message structure definition



def drawBox(boxPlt, boxX1, boxX2, boxY, text):
    '''
    Draw a box, centred on a line at height boxY, at a point boxX, with a segment name inside
    '''
    logging.info('Renderining box(%s) from %d to %d at height %d', text, boxX1, boxX2, boxY)
    thisX = [boxX1, boxX2, boxX2, boxX1, boxX1]
    thisY = [boxY + 50, boxY + 50, boxY - 50, boxY - 50, boxY + 50]
    boxPlt.plot(thisX, thisY, color='0')
    boxPlt.text(boxX1 + 30, boxY, text, color='0')
    return


def drawOptional(optPlt, optX1, optX2, optY, optDepth):
    '''
    Draw an 'optional' arrow on a line at heigh optY, below boxes from optX1 to optX2
    '''
    logging.info('Rendering optional line from %d to %d at height %d with dept %d',
                  optX1, optX2, optY, optDepth)
    down = optY - 50 - (optDepth * 10)
    thisX = [optX1, optX1, optX2]
    thisY = [optY, down, down]
    optPlt.plot(thisX, thisY, color='0')
    optPlt.arrow(optX2, down, 0, optY - down - 4, length_includes_head=True, head_width=5, color='0', linewidth=1)
    return


def drawRepeat(rptPlt, rptX1, rptX2, rptY, rptDepth):
    '''
    Draw an 'repeat' arrow on a line at heigh optY, below boxes from optX2 back to optX1
    '''
    logging.info('Rendering repeat line from %d to %d at height %d with dept %d',
                  rptX1, rptX2, rptY, rptDepth)
    up = rptY + 50 + (rptDepth * 10)
    thisX = [rptX2, rptX2, rptX1]
    thisY = [rptY, up, up]
    rptPlt.plot(thisX, thisY, color='0')
    rptPlt.arrow(rptX1, up, 0, rptY - up + 4, length_includes_head=True, head_width=5, color='0', linewidth=1)
    return


def getBoxes(sequence, depth):
    '''
    Get the boxes associated with this segment grouping
    '''
    maxDepth = depth
    chain = []
    thisLength = 0      # Total length of everything
    for ii, element in enumerate(sequence):
        chainBox = {}
        name = element.attrib['ref']
        opt = element.attrib['minOccurs']
        rpt = element.attrib['maxOccurs']
        chainBox['name'] = element.attrib['ref']
        chainBox['minOccurs'] = element.attrib['minOccurs']
        chainBox['maxOccurs'] = rpt
        if len(name) == 3:      # A segment
            chainBox['depth'] = 1
            chainBox['length'] = 100
            thisLength += 100
            if (opt == '0') or (rpt == 'unbounded'):
                thisLength += 20
            if ii < (len(sequence) - 1):
                thisLength += 50
            chainBox['maxDepth'] = 1
            chain.append(chainBox)
            continue
        childSequence = messageRoot.find("xsd:complexType[@name='" + name + ".CONTENT']/xsd:sequence", namespaces)
        if childSequence is None:       # Must be a choice - single box
            childSequence = messageRoot.find("xsd:complexType[@name='" + name + ".CONTENT']/xsd:choice", namespaces)
            name = ''
            choiceLen = 0
            for choice in childSequence:
                if name != '':
                    name += '|'
                    choiceLen += 10
                name += choice.attrib['ref']
                choiceLen += 45
            chainBox['name'] = name
            chainBox['depth'] = 1
            chainBox['length'] = choiceLen
            thisLength += choiceLen
            if (opt == '0') or (rpt == 'unbounded'):
                thisLength += 20
            if ii < (len(sequence) - 1):
                thisLength += 50
            chainBox['maxDepth'] = 1
            chain.append(chainBox)
            continue
        # Group of a sequence of segments/segment groups
        childLength, newDepth, newChain = getBoxes(childSequence, depth + 1)
        logging.info('Group of segments called %s, length %d, at depth %d, newDepth %d, chain:%s', name, childLength, depth + 1, newDepth, repr(newChain))
        if newDepth > maxDepth:
            maxDepth = newDepth
        chainBox['depth'] = depth + 1
        chainBox['length'] = childLength
        thisLength += chainBox['length']
        if (opt == '0') or (rpt == 'unbounded'):
            thisLength += 20
        if ii < (len(sequence) - 1):
            thisLength += 50
        chainBox['chain'] = newChain
        chainBox['maxDepth'] = maxDepth
        chain.append(chainBox)
    return thisLength, maxDepth, chain


def renderBoxes(boxPlt, boxList, startX, thisY, maxDepth):
    '''
    Render a list of boxes on a line at thisY, starting at position startX on that line
    PARAMETERS:
        boxPlt - matplotlib pyplot
        boxList - list, list of block structures to render
        startX - int, start of line position
        thisY - int, current line height
    '''
    endX = startX
    for ii, thisBox in enumerate(boxList):
        thisX = endX
        endBox = thisX + thisBox['length']
        realDepth = maxDepth + 2 - thisBox['depth']
        if thisBox['depth'] == 1:
            realDepth = 1
            endX += thisBox['length']
            logging.info('Rendering group block(%s), opt(%s), rpt(%s), depth(%s), maxDepth(%d), length(%d)',
                            thisBox['name'], thisBox['minOccurs'], thisBox['maxOccurs'], thisBox['depth'], maxDepth, thisBox['length'])
            drawBox(boxPlt, thisX, endBox, thisY, thisBox['name'])
        else:
            logging.info('Rendering group of block(%s), opt(%s), rpt(%s), depth(%s), maxDepth(%d), length(%d)',
                            thisBox['name'], thisBox['minOccurs'], thisBox['maxOccurs'], thisBox['depth'], maxDepth, thisBox['length'])
            newX = renderBoxes(boxPlt, thisBox['chain'], endX, thisY, maxDepth)
            logging.info('Block rendered at %d, of length %d, endX now %d, endBox(%d)', endX, thisBox['length'], newX, endBox)
            endX = newX
        x0 = endBox
        x1 = endBox
        if ii < (len(boxList) - 1):     # Not the last box
            x1 += 50
            if (boxList[ii + 1]['minOccurs'] == '0') or (boxList[ii + 1]['maxOccurs'] == 'unbounded'):
                x1 += 10
        if (thisBox['minOccurs'] == '0') or (thisBox['maxOccurs'] == 'unbounded'):      # Need arrow(s)
            x1 += 10
        if x0 != x1:
            endX = x1
            boxX = [x0, x1]
            boxY = [thisY, thisY]
            logging.info('End of block line from %d to %d at height %d', x0, x1, thisY)
            plt.plot(boxX, boxY, color='0')
        if (thisBox['minOccurs'] == '0') or (thisBox['maxOccurs'] == 'unbounded'):      # Need arrow(s)
            x0 = thisX - 10
            x1 = endBox + 10
            if thisBox['minOccurs'] == '0':              # Need optional arrow
                drawOptional(boxPlt, x0, x1, thisY, realDepth)
            if thisBox['maxOccurs'] == 'unbounded':       # Need repeat arrow
                drawRepeat(boxPlt, x0, x1, thisY, realDepth)
    logging.info('Returning endX at %d', endX)
    return endX


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
                        help='The folder where the ".png" file will be saved [messageStructure.png] (default="schema/v2.4")')
    parser.add_argument('-o', '--outputFile', dest='outputFile', default=None,
                        help='The filename of the ".png" file to be create (default="messageStructure.png")')
    parser.add_argument ('-v', '--verbose', dest='verbose', type=int, choices=range(0,5),
                         help='The level of logging\n\t0=CRITICAL,1=ERROR,2=WARNING,3=INFO,4=info')
    parser.add_argument ('-L', '--logDir', dest='logDir', default='.', metavar='logDir',
                         help='The name of the directory where the logging file will be created')
    parser.add_argument ('-l', '--logFile', dest='logFile', metavar='logfile', help='The name of a logging file')

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
    logging_levels = {0:logging.CRITICAL, 1:logging.ERROR, 2:logging.WARNING, 3:logging.INFO, 4:logging.info}
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

    # Check that the schemaDir folder exist
    if not os.path.isdir(schemaDir):
        logging.critical('No schemaDir folder named "%s"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if not os.path.isdir(os.path.join(schemaDir, 'xsd')):
        logging.critical('No schemaDir folder named "%s/xsd"', schemaDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)

    # Check that the message structure file exists and read it in
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

    # Now create the HL7 v2.x train diagram
    maxLength, deepestDepth, boxChain = getBoxes(segmentList, 1)

    # Layout the boxes on lines on the page
    lines = []
    lines.append({})
    maxX = 1600
    X = 50
    Y = 100
    first = True
    for box in boxChain:
        if first:
            X = 50
            Y = 100
            lines[0]['Y'] = Y
            lines[0]['maxDepth'] = box['maxDepth']
            lines[0]['boxes'] = []
            logging.info('New line - maxDepth(%d)', lines[0]['maxDepth'])
            first = False
        if (X + box['length'] + box['depth'] * 20) < 1300:  # Another box set for this line
            logging.info('Appending another box to line - name(%s), maxDepth(%d)', box['name'], box['maxDepth'])
            box['X'] = X + box['depth'] * 10
            lines[0]['boxes'].append(box)
            logging.info('Comparing this box maxDepth(%s) with current line maxDepth(%d)', box['maxDepth'], lines[0]['maxDepth'])
            if box['maxDepth'] > lines[0]['maxDepth']:
                lines[0]['Y'] += (box['depth'] - lines[0]['maxDepth']) * 10      # Allow for any optional arrows
                lines[0]['maxDepth'] = box['maxDepth']
            X += box['length'] + box['depth'] * 20 + 50
        else:           # Time for a new line
            X = 80          # Allow for lead-in tilda
            Y = lines[0]['Y'] + 150 + lines[0]['maxDepth'] * 10        # Allow for any repeat arrows
            lines.insert(0, {})
            lines[0]['Y'] = Y + box['depth'] * 10
            lines[0]['maxDepth'] = box['maxDepth']
            lines[0]['boxes'] = []
            lines[0]['boxes'].append(box)
            logging.info('New line - maxDepth(%d)', lines[0]['maxDepth'])
            X += box['length'] + box['depth'] * 20 + 50
            if (X + 50) > maxX:
                maxX = int((X + 50 + 99) / 100) * 100

    # Construct a page for this diagram
    topY = int((lines[0]['Y'] + 180 + lines[0]['maxDepth'] * 10 + 99)/100) * 100
    fig, ax = plt.subplots(figsize=(maxX / 100.0, topY / 100.0), dpi=100)      # canvas
    plt.axis('off')
    plt.xlim((0, maxX))
    plt.ylim((0, topY))
    plt.text(int(maxX / 20) * 10, topY - 20, msgStruct)

    # Render the lines on this page
    # Lines are rendered in reverse order (lines[0] is the last line at the bottom of the canvas)
    for i, line in enumerate(lines):
        logging.info('Rendering line %d of boxes with boxes %s', i, repr(line))
        Y = topY - line['Y']
        X = 80
        if i < (len(lines) - 1):        # Starting a second, or subsequent line = start with the joiner character
            plt.text(20, Y, '~', rotation=90, color='0')
            x = [35, 80]
            y = [Y, Y]
            plt.plot(x, y, color='0')
        # Render each block, or group of blocks
        X = renderBoxes(plt, line['boxes'], X, Y, line['maxDepth'])
        if i > 0:      # Not the last line - need a tilda
            x = [X, X + 45]
            y = [Y, Y]
            plt.plot(x, y, color='0')
            plt.text(X + 45, Y, '~', rotation=90, color='0')
        continue

    # Save the rendered image
    if outputFile is None:
        outputFile = msgStruct + '.png'
    if outputDir is not None:
        outputFilename = os.path.join(outputDir, outputFile)
    else:
        outputFilename = outputFile
    plt.savefig(outputFilename)
    # plt.show()
