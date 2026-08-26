# pylint: disable=line-too-long
'''
Script parseAppendixA.py
A script to extract the tables from HL7 Appendix A.
This script can only read AppendixA.docx, which mean you will have to us Word
to open the default AppendixA.doc and save it as a Word Document (.docx)


    SYNOPSIS
    $ python parseAppendixA.py [-I inputDir|--inputDir=inputDir]
        [-i inputFile|--inputFile=inputFile]
        [-O outputDir|--outputDir=outputDir]
        [-S schemaDir|--schemaDir=schemaDir]
        [-v loggingLevel|--verbose=logingLevel]
        [-L logDir|--logDir=logDir]
        [-l logfile|--logfile=logfile]


    REQUIRED


    OPTIONS
    -I inputDir|--inputDir=inputDir              [Optional - one of inputDir or schemaDir must be specified]
    The folder containing the HL7 Appendix A Word document(.docx)

    -i inputFile|--inputFile=inputFile
    The name of the HL7 Appendix A Word document.

    -O outputDir|--outputDir=outputDir
    The folder where the output file (Appendix A.xlsx) will be created.

    -o outputFile|--outputFile=outputFile
    The name of the output file (default "Appendix A.xlsx").

    -S schemaDir|--schemaDir=schemaDir             [Optional - one of inputDir or schemaDir must be specified]
    The folder containing the HL7 Appendix A Word document(.docx)

    -v loggingLevel|--verbose=loggingLevel
    Set the level of logging that you want.

    -L logDir|--logDir=logDir
    The directory where the log file will be created (default=".").

    -l logfile|--logfile=logfile
    The name of a log file where you want all log messages captured.
'''

# pylint: disable=invalid-name, bare-except, pointless-string-statement, global-statement; superfluous-parens

import os
import sys
import logging
import argparse
import re
from docx import Document   # Import the Document class from the docx module to work with Word documents
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
    Then parse Appendix A.docx and create AppendixA.xlsx
    '''

    # Set the command line options
    progName = sys.argv[0]
    progName = progName[0:-3]        # Strip off the .py ending
    parser = argparse.ArgumentParser(description='parseAppendixA')
    parser.add_argument('-I', '--inputDir', dest='inputDir', default=None,
                        help='The folder containing the HL7 AppendixA.docx file)')
    parser.add_argument('-i', '--inputFile', dest='inputFile', default='AppendixA.docx',
                        help='The name of the HL7 AppendixA.docx file (default="AppendixA.docx)')
    parser.add_argument('-O', '--outputDir', dest='outputDir', default='.',
                        help='The folder where the HL7 v2.xml XML tagged message(s) will be created (default=".")')
    parser.add_argument('-o', '--outputFile', dest='outputFile', default='Appendix A.xlsx',
                        help='The name of the HL7 Appendix A.xlsx file (default="Appendix A.xlsx")')
    parser.add_argument('-S', '--schemaDir', dest='schemaDir', default=None,
                        help='The folder containing the HL7 AppendixA.docx file)')
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

    # Initialize an empty list to store tables
    sheet_names = ['Appendix A.3 Message Types', 'Appendix A.4 Segments', 'Appendix A.5 Tables Alphabetic', 'Appendix A.6 Tables Numeric', 'Appendix A.7 Data Element Names']
    tables = []

    # Iterate through each table in the document
    for t, table in enumerate(document.tables):
        # Create a DataFrame structure with empty strings, sized by the number of rows and columns in the table
        df = [['' for _ in range(len(table.columns))] for _ in range(len(table.rows))]
        
        # Iterate through each row in the current table
        for i, row in enumerate(table.rows):
            # Iterate through each cell in the current row
            for j, cell in enumerate(row.cells):
                # If the cell has text, store it in the corresponding DataFrame position
                if cell.text:
                    df[i][j] = cell.text
             
        # Convert the list of lists (df) to a pandas DataFrame and add it to the tables list
        dfTable = pd.DataFrame(df)
        logger.debug('%s - from Word', sheet_names[t])
        logger.debug(dfTable.head(20).to_string(header=False, index=False), extra={'raw_message': True})
        logger.debug('\n', extra={'raw_message': True})

        # Special Processing for HL7 Version 2.4 - your version may have similar problems
        # Alpabetic Tables has columns 1 and 2 merged in the header, but columns 0 and 1 merged in the data
        # Deleting columns by duplicate name would delete column 2 which is where the Table data is.
        # So just delete column 1 (first Table heading and duplicate Type data)
        if t == 2:      # Table Alphabetic has a particular problem
            dfTable = dfTable.drop(dfTable.columns[1], axis=1)  # The merge cells in heading doesn't match the merged columns in the data

        # Fix up/delete duplated columns caused by merged cells (columns)
        dfTable.columns = dfTable.iloc[0]   # Promote the first row to column names. We output without column names, so it doesn't matter what we put here
        dfTable = dfTable.loc[:,~dfTable.columns.duplicated()].copy()   # Remove duplicate columns

        if t == 3:      # Table Numeric has some data quality issues - the OCE edit codes (Table 0458) sometimes have a trailing '.'
            dfTable.loc[dfTable['Table'] == '0458', 'Value'] = dfTable.loc[dfTable['Table'] == '0458', 'Value'].astype(str).str.rstrip('.')

        logger.debug('%s - to Excel', sheet_names[t])
        logger.debug(dfTable.head(20).to_string(header=False, index=False), extra={'raw_message': True})
        logger.debug('\n', extra={'raw_message': True})

        # Save this table
        tables.append(dfTable)

    # Check that we have 5 tables
    if len(tables) != 5:
        logger.critical("Word docuement doesn't contain 5 tables - is has %d", len(tables))
        logging.shutdown()
        sys.exit(EX_DATAERR)

    # Save the tables in an Excel workbook
    with pd.ExcelWriter(os.path.join(outputDir, outputFile), engine='openpyxl') as ExcelWriter:
        for i, df in enumerate(tables):
            df.to_excel(ExcelWriter, sheet_name=sheet_names[i], header=None, index=False)
