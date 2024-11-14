# HL7-Validator
Validate HL7 vertical bar messages

**HL7 Validator** validates an HL7 vertical bar message against the equivalent HL7 v2.xml Schema.  
HL7 v2.xml XML Schema definitions, for various HL7 v2.x versions, can be obtained from [HL7 International](https://www.hl7.org/).

The HL7 v2.xml Schema contain sufficient information for **HL7 Validator** to detect

* Unexepected segments in a message
* Additional, unexpected fields at the end of a segment
* Unexpected repetitions in a field
* Additional, unexpected components and subcomponents

The HL7 v2.xml Schemas also contain information about data types, which **HL7 Validator** uses to check for incorrectly formatted data in fields,
components and subcomponents, such as date/time data, encoded encapsulated data, numeric indicators etc.

The HL7 v2.xml Schemas are a set of schemas, one for each message structure, e.g. ADT_A01, ORU_R01 etc.
There is one set for each HL7 v2.x version. **HL7 Validator** expects each set to be stored in a separate folder, called the "Schema Directory".
The path to the "Schema Directory" is a required command line argument.
**HL7 Validator** makes no attempt to check that the HL7 v2.xml Schemas in the "Schema Directory" matches the version of the message being validated.

The message structure for each message can be encoded in MSH-9.3, but this is optional.
Fortunately it can be inferred from MSH-9.1 [Message Code] and MSH-9.2 [Trigger Event] using HL7 Table 0354.
To enable this mapping **HL7 Validator** requires the user to configure a CSV file (tab separated) called "hl7Table0354.csv"
which contains the "Value" and "Description" columns from Appendix A.6 from the matching HL7 v2.x standard.
The file "hl7Tables0354.csv" must exist in the "Schema Directory".
A subfolder of the "Schema Directory", named "xsd", must exist and this is where **HL7 Validator** expect to find all the HL7 v2.xml Schema files (*.xsd).

 Copies of HL7 v2.x Standards, which include Appendix A, can be obtained from [HL7 International](https://www.hl7.org/).

The HL7 v2.xml Schema also identify any matching HL7 or User defined table associated with a field, component of subcomponent,
but not the actual codes contained in those tables.
**HL7 Validator** checks for the existance of a file called "hl7Tables.csv" in the "Schema Directory".
If this file exists it must a tab separated file of the data from the "Type", "Table", "Name" and "Value" columns from Appendix A.6 of the matching HL7 v2.x standard.
**HL7 Validator** will read this file and use it to validate the data in any field, component or subcomponent with a matching HL7 or User defined table
against the codes found in the "hl7Tables.csv" file.

The HL7 v2.x standards also define the maximum length for each field.
**HL7 Validator** checks for the existance of a file called "hl7Fields.csv" in the "Schema Directory".
If this file exists it must a tab separated file of the data from the "Seg", "Seq#" and "Len" columns from Appendix A.7 of the matching HL7 v2.x standard.
**HL7 Validator** will read this file and use it to validate the length of the data in each matching field.

Later version of the HL7 v2.x standard also defines maximum lengths for data types which can exist in any field, component of subcomponent.
**HL7 Validator** checks for the existance of a file called "hl7DataTypes.csv" in the "Schema Directory".
If this file exists it must a tab separated file of two columns being "DT/SEQ" and "LEN".
Any non-numeric value in the "DT/SEQ" column is assumed to be a data type. Any numeric value in the "DT/SEQ" column is assumed to be the sequence location,
within the last named data type, and the "LEN" column must contain a length value for the matching item within the data type.
**HL7 Validator** will read this file and use it to validate the length of the data in each matching component or subcomponent item
where the component or subcomponent has the specified data type.

## Value Sets
The pattern Identifier/Description/Coding System occurs frequently in HL7 v2.x messages.
Here the Identifier should be a valid code from the Coding System.
Often the set of valid Identifiers is restricted to a subset of all of the values from the Coding System; a subset or value set.
**HL7 Validator** checks for the existance of a file called "valueSets.csv" in the "Schema Directory".
If this file exists it must a tab separated file of three columns being "FIELD/COMPONENT", "SYSTEM" and "CODE". e.g.

FIELD/COMPONENT SYSTEM  CODE  
OBX-3   LN  1554-5  
OBX-3   LN  3137-7  
DG1.4   I10 R63.4  

Which would mean that "1554-5" would be a valid identifier in field 3 of any OBX segment, if the "coding system" was specified as "LN".
"3137-7" would also be valid, but any other "LN" identifier would be invalid.
The specified Field or Component should be one which has one of the coding data type [CE, CF, CNE, CWE] which have two sets of coding,
with the second set being an alternative coding. **HL7 Validator** will test both coding sets if they both exist.
If, in a specified field/component, the "coding system" is one that does not exist in the file "valueSets.csv" then no validation is performed;
unknown codes from unknown coding systems are not an error.

**Note:** it may be necessary to configure up more than one instance of **HL7 Validator** - potentially one per interface,
as the LOINC code acceptable in one interface (e.g. Pathology results) may be different to the set of LOINC codes in another interface (e.g. Radiology reports).
Similarly, an interface may use just a small subset of message types, so you may choose to delete any unused message structure schema definition files.
You may also want to expand the HL7 v2.xml schema specification to include definitions for any local Z-segments.