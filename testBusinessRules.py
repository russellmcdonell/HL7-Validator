# pylint: disable=line-too-long
'''
Script to test a Business Rules DMN.xlsx Decision Model Notation (DMN) rules Workbook
'''

import os
import sys
import argparse
import logging
import pyDMNrules

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
    '''
    For raw output (not logger preamble) use
        logger.info('Message with no preamble', extra={'raw_message: True})
    '''
    def format(self, record):
        if hasattr(record, 'raw_message') and record.raw_message:
            return record.getMessage()
        else:
            return super().format(record)




if __name__ == '__main__':
    '''
    The main code
    '''

    # Save the program name
    progName = (sys.argv[0])[0:-3]

    # Set up the command line arguments
    parser = argparse.ArgumentParser(description='testBusinessRules')
    parser.add_argument('-S', '--schemaDir', dest='schemaDir', required=True, default='schema/v2.4',
                        help='The folder containing the HL7 v2.xml XML schema files (default="schema/v2.4")')
    parser.add_argument('-R', '--RulesFile', dest='rulesFile', required=True, default='Business Rules DMN.xlsx',
                        help='The folder containing the HL7 v2.xml XML schema files (default="schema/v2.4")')
    parser.add_argument ('-v', '--verbose', dest='verbose', type=int, choices=range(0,5),
                         help='The level of logging\n\t0=CRITICAL,1=ERROR,2=WARNING,3=INFO,4=DEBUG')
    parser.add_argument ('-L', '--logDir', dest='logDir', default='.', metavar='logDir',
                         help='The name of the directory where the logging file will be created')
    parser.add_argument ('-l', '--logFile', dest='logFile', metavar='logfile', help='The name of a logging file')
    args = parser.parse_args()

    # Set up logging
    loggingLevels = {0:logging.CRITICAL, 1:logging.ERROR, 2:logging.WARNING, 3:logging.INFO, 4:logging.DEBUG}
    logger = logging.getLogger(__name__)
    if args.verbose:
        logger.setLevel(loggingLevels[args.verbose])
    else:
        logger.setLevel(logging.INFO)
    if args.logFile:
        handler = logging.FileHandler(os.path.join(args.logDir, args.logFile))
    else:
        handler = logging.StreamHandler()
    logformat = progName + ' %(levelname)s[%(asctime)s]: %(message)s'
    dateformat = '%d/%m/%y %H:%M:%S %p'
    formatter = ConditionalFormatter(logformat, dateformat)
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.info("Debug started")

    # Parse the optional arguments
    schemaDir = args.schemaDir
    rulesFile = args.rulesFile

    # Initialize the Rules Engine
    dmnRules = pyDMNrules.DMN()
    status = dmnRules.load(os.path.join(schemaDir, rulesFile))

    if 'errors' in status:
        logger.critical('test_Business Rules DMN.xlsx has errors')
        for i, error in enumerate(status['errors']):
            logger.critical(error, extra={'raw_message': True})
        logging.shutdown()
        sys.exit(EX_CONFIG)
    logger.info(f'{os.path.join(schemaDir, rulesFile)} loaded')
    glossary = dmnRules.getGlossary()
    logger.debug(f'Glossary after load():', extra={'raw_message': True})
    w = [0, 0, 0]
    for businessConcept in glossary:
        if len(businessConcept) > w[0]:
            w[0] = len(businessConcept)
        for variable in glossary[businessConcept]:
            if len(variable) > w[1]:
                w[1] = len(variable)
            name, value, descriptions = glossary[businessConcept][variable]
            if len(name) > w[2]:
                w[2] = len(name)
    for businessConcept in glossary:
        for variable in glossary[businessConcept]:
            name, value, descriptions = glossary[businessConcept][variable]
            for i, description in enumerate(descriptions):
                if description is None:
                    descriptions[i] = ""
            logger.debug(f'Variable:{variable:{w[1]+5}}Business Concept:{businessConcept:{w[0]+5}}Name:{name:{w[2]+5}}Description(s):{",".join(descriptions)}', extra={'raw_message': True})
    logger.debug('', extra={'raw_message': True})

    data = {}
    data['Rule'] = 'HL7au:00044.7.1'
    data['XCN.1'] = '419786CW'
    data['XCN.2.1'] = "CRUICE"
    data['XCN.3'] = "ANTHONY"
    data['XCN.9'] = 'AUSHICPR'
    data['XCN.13'] = 'UPIN'
    logger.info('Testing: %s\n',repr(data))
    (status, newData) = dmnRules.decide(data)
    logger.info('Decisions', extra={'raw_message':True})
    if isinstance(newData, list):
        for i, result in enumerate(newData):
            for section in result:
                logger.info('Section:%s', section, extra={'raw_message':True})
                logger.info('%s', repr(result[section]), extra={'raw_message':True})
            logger.info('', extra={'raw_message':True})
        if newData != []:
            result = newData[-1]
        else:
            result = newData
    else:
        result = newData
        for section in result:
            logger.info('Section:%s', section, extra={'raw_message':True})
            logger.info('%s', repr(result[section]), extra={'raw_message':True})
        logger.info('', extra={'raw_message':True})
    logger.debug(f'Glossary after decide():', extra={'raw_message':True})
    glossary = dmnRules.getGlossary()
    w = [0, 0, 0, 0]
    for businessConcept in glossary:
        if len(businessConcept) > w[0]:
            w[0] = len(businessConcept)
        for variable in glossary[businessConcept]:
            if len(variable) > w[1]:
                w[1] = len(variable)
            name, value, descriptions = glossary[businessConcept][variable]
            if len(name) > w[2]:
                w[2] = len(name)
            if len('None' if value is None else str(value)) > w[3]:
                w[3] = len('None' if value is None else str(value))
    for businessConcept in glossary:
        for variable in glossary[businessConcept]:
            name, value, descriptions = glossary[businessConcept][variable]
            for i, description in enumerate(descriptions):
                if description is None:
                    descriptions[i] = ""
            if value is None:
                value = 'None'
            else:
                value = str(value)
            logger.debug(f'Variable:{variable:{w[1]+5}}Business Concept:{businessConcept:{w[0]+5}}Name:{name:{w[2]+5}}Value:{value:{w[3]+5}}Description(s):{",".join(descriptions)}', extra={'raw_message': True})
    logger.debug('', extra={'raw_message': True})
    if 'errors' in status:
        logger.critical('With errors', extra={'raw_message':True})
        for i, error in enumerate(status['errors']):
            logger.critical(error, extra={'raw_message':True})
    else:
        logger.info('Tested')
        if "Result" in result:
            if "Passed" not in result["Result"]:
                logger.critical(f'Rule:{data["Rule"]} failed to set "Passed"')
                logging.shutdown()
                sys.exit(EX_CONFIG)
            elif result["Result"]["Passed"] == True:
                logger.info(f'The Data passed testing')
            elif result["Result"]["Passed"] == False:
                logger.critical(f'The Data failed testing: {result["Result"]["Reason"]}')
                logging.shutdown()
                sys.exit(EX_DATAERR)
            else:
                logger.critical(f'Rule:{data["Rule"]} returned invalid value for "Passed" - ({result["Result"]["Passed"]})')
                logging.shutdown()
                sys.exit(EX_CONFIG)
        else:
            logger.critical("decide() returned no results")
            logging.shutdown()
            sys.exit(EX_CONFIG)

    logger.info('', extra={'raw_message':True})

