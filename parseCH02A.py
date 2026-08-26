# pylint: disable=line-too-long
'''
Script parseCH02A.py
A script to extract the data type tables from HL7 Chapter 2A.
This script can only read CH02A.docx, which mean you will have to us Word
to open the default CH02A.doc and save it as a Word Document (.docx)


    SYNOPSIS
    $ python parseCH02A.py [-I inputDir|--inputDir=inputDir]
        [-i inputFile|--inputFile=inputFile]
        [-O outputDir|--outputDir=outputDir]
        [-S schemaDir|--schemaDir=schemaDir]
        [-v loggingLevel|--verbose=logingLevel]
        [-L logDir|--logDir=logDir]
        [-l logfile|--logfile=logfile]


    REQUIRED


    OPTIONS
    -I inputDir|--inputDir=inputDir              [Optional - one of inputDir or schemaDir must be specified]
    The folder containing the HL7 Chapter 2A Word document(.docx)

    -i inputFile|--inputFile=inputFile
    The name of the HL7 Chapter 2A Word document (default CH02A.docx).

    -O outputDir|--outputDir=outputDir
    The folder where the output file (data types.xlsx) will be created.

    - outputFile|--outputFile=outputFile
    The name of the output file (default data types.xlsx).

    -S schemaDir|--schemaDir=schemaDir              [Optional - one of inputDir or schemaDir must be specified]
    The folder containing the HL7 Chapter 2A Word document(.docx)

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
from docx import Document   # Import the Document class from the docx module to work with Word documents
from docx.text.paragraph import Paragraph
from docx.table import Table
import pandas as pd         # Import pandas for data manipulation and analysis


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
    Then process each file name in the command line - read the HL7 v2.x vertical bar message
    and convert it an HL7 v2.xml XML tagged message
    '''

    # Set the command line options
    progName = sys.argv[0]
    progName = progName[0:-3]        # Strip off the .py ending
    parser = argparse.ArgumentParser(description='parseCH02A')
    parser.add_argument('-I', '--inputDir', dest='inputDir', default=None,
                        help='The folder containing the HL7 CH02A.docx file')
    parser.add_argument('-i', '--inputFile', dest='inputFile', default='CH02A.docx',
                        help='The name of the HL7 CH02A.docx file (default="CH02A.docx)')
    parser.add_argument('-O', '--outputDir', dest='outputDir', default='.',
                        help='The folder where data types.xlsx will be created (default=".")')
    parser.add_argument('-o', '--outputFile', dest='outputFile', default='data types.xlsx',
                        help='The name of the data types.xlsx file (default="data types.xlsx")')
    parser.add_argument('-S', '--schemaDir', dest='schemaDir', default=None,
                        help='The folder containing the HL7 CH02A.docx file')
    parser.add_argument ('-v', '--verbose', dest='verbose', type=int, choices=range(0,5),
                         help='The level of logging\n\t0=CRITICAL,1=ERROR,2=WARNING,3=INFO,4=DEBUG')
    parser.add_argument ('-L', '--logDir', dest='logDir', default='.', metavar='logDir',
                         help='The name of the directory where the logging file will be created')
    parser.add_argument ('-l', '--logFile', dest='logFile', metavar='logfile', help='The name of a logging file')

    # Parse the command line
    args = parser.parse_args()
    inputDir = args.inputDir
    inputFile = args.inputFile
    outputDir = args.outputDir
    outputFile = args.outputFile
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
    dateformat = '%d/%m/%y %H:%M:%S %p'
    formatter = ConditionalFormatter(logformat, dateformat)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.debug('Logging set up')

    # Check that we have an input folder
    if (inputDir is None) and (schemaDir is None):
        logger.critical('Neither inputDir nor schemaDir specified - one must be specified')
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if (inputDir is not None) and (schemaDir is not None):
        logger.critical('Both inputDir and schemaDir specified - only one must be specified')
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if inputDir is None:
        inputDir = schemaDir
    
    if not os.path.isdir(inputDir):
        logger.critical('No folder named "%s"', inputDir)
        logging.shutdown()
        sys.exit(EX_CONFIG)
    if not os.path.isfile(os.path.join(inputDir, inputFile)):
        logger.critical('No file (%s) in folder (%s)', inputDir, inputFile)
        logging.shutdown()
        sys.exit(EX_CONFIG)

    # Load the Word document - assumes that you've openen AppendixA.doc in Word and saved it as a .docx file
    document = Document(os.path.join(inputDir, inputFile))

    # Initialize the data types DataFrame
    dfDataTypes = pd.DataFrame()

    # Iterate through the document
    first = True
    for block in document.element.body.iterchildren():
        if block.tag.endswith('p'):         # A Paragraph
            para = Paragraph(block, document)
        elif block.tag.endswith('tbl'):
            if not para.text.startswith('HL7 Component Table'):
                continue
            dataType = para.text[20:]
            while (len(dataType) > 0) and (re.match(r'[A-Z0-9]', dataType[0]) is None):
                dataType = dataType[1:]
            if len(dataType) == 0:
                continue
            i = 0
            while (i < len(dataType)) and (re.match(r'[A-Z0-9]', dataType[i:i + 1]) is not None):
                i += 1
            if i == len(dataType):
                continue
            dataType = dataType[0:i]

            table = Table(block, document)
            # Create a DataFrame structure with empty strings, sized by the number of rows and columns in the table
            if first:
                df = [['' for _ in range(len(table.columns) + 1)] for _ in range(len(table.rows))]
            else:
                df = [['' for _ in range(len(table.columns) + 1)] for _ in range(len(table.rows) - 1)]
            
            # Iterate through each row in the current table
            for i, row in enumerate(table.rows):
                if i == 0:
                    if first:
                        df[0][0] = "data type"
                    else:
                        continue
                else:
                    if first:
                        df[i][0] = dataType
                    else:
                        df[i - 1][0] = dataType

                # Iterate through each cell in the current row
                for j, cell in enumerate(row.cells):
                    # If the cell has text, store it in the corresponding DataFrame position
                    if cell.text:
                        if first:
                            df[i][j + 1] = cell.text
                        else:
                            df[i - 1][j + 1] = cell.text
            first = False
             
             
            # Convert the list of lists (df) to a pandas DataFrame and add it to the tables list
            dfTable = pd.DataFrame(df)
            dfDataTypes = pd.concat([dfDataTypes, dfTable])


    # Save the tables in an Excel workbook
    with pd.ExcelWriter(os.path.join(outputDir, outputFile), engine='openpyxl') as ExcelWriter:
        dfDataTypes.to_excel(ExcelWriter, sheet_name='data types', header=None, index=False)
