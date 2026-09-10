
# HL7-Validator

Validate HL7 vertical bar messages and optionally, check for conformance to specified business rules.

## Validation

**HL7 Validator** validates an HL7 vertical bar message against the equivalent HL7 v2.xml Schema.  
HL7 v2.xml XML Schema definitions, for various HL7 v2.x versions, can be obtained from [HL7 International](https://www.hl7.org/).

### HL7 v2.xml Schema

The HL7 v2.xml Schema contain sufficient information for **HL7 Validator** to detect

* Unexepected segments in a message
* Additional, unexpected fields at the end of a segment
* Unexpected repetitions in a field
* Additional, unexpected components and subcomponents

The HL7 v2.xml Schemas also contain information about data types, which **HL7 Validator** uses to check for incorrectly formatted data in fields, components and subcomponents, such as date/time data, encoded encapsulated data, numeric indicators etc.

The HL7 v2.xml Schemas are a set of schemas, one for each message structure, e.g. ADT_A01, ORU_R01 etc.
There is one set for each HL7 v2.x version. **HL7 Validator** expects each set to be stored in a separate folder, called the "Schema Directory". The path to the "Schema Directory" is a required command line argument. **HL7 Validator** makes no attempt to check that the HL7 v2.xml Schemas in the "Schema Directory" matches the version in the MSH segment of the message being validated.

The message structure for each message can be encoded in MSH-9.3, but this is optional. Fortunately it can be inferred from MSH-9.1 [Message Code] and MSH-9.2 [Trigger Event] using HL7 Table 0354 which can be found in **Appendix A** of the HL7 V2.x Stanrdard for each HL7 v2.x version. A subfolder of the "Schema Directory", named "xsd", must exist and this is where **HL7 Validator** expect to find all the HL7 v2.xml Schema files (*.xsd).

 Copies of HL7 v2.x Standards, which include Appendix A, can be obtained from [HL7 International](https://www.hl7.org/). You can also download the HL7 v2.x XML Schemas from [HL7 International](https://www.hl7.org/).

### Appendix A

The HL7 v2.x standards also define the maximum length for each field. Field lengths can be found in Appendix A.7 of the HL7 Standard.

The HL7 v2.xml Schema also identify any matching HL7 or User defined table associated with fields, components and subcomponents,
but **not** the actual codes contained in those tables. Valid codes can be found in Appendix A.6 of the HL7 v2.x Standard.

**HL7 Validator** uses an Excel Workbook called "**Appendix A.xlsx**" which must exist in the "Schema Directory".
This Excel Workbook **must have** a worksheet named "**Appendx A.6 Tables Numeric**" with column heading of "Type", "Table", "Name", "Value" and "Description".
Data from the "Type", "Table" and "Value" columns will be used to validate data in fields, components and subcomponent
associated with this HL7 or User defined table. This worksheet **must define values for HL7 Table 0354**, being the Message Structure for each Trigger Event.

If this Excel Workbook has a worksheet named "**Appendix A.7 Data Element Names*", then this worksheet must have column headings of "Description", "Item#", "Seg", "Seq#", "Len", "DT", "Rep", "Table", "Chap". The data in columns "Seg", "Seq#" and "Len" will be used to validate the lengths of fields.

NOTE: If you try to create "**Appendix A.xlsx*" by copy and paste from the Word or PDF version of AppendixA, then you will have issues
with Table numbers, Item# and Values which have leading zeros, which get lost in copy and paste. Also, Values which have decimal points will be saved a numbers (HL7 Version 2.3 becomes 2.299999999). A safer way to create "**Appendix A.xlsx**" is to use the Python scripts "parseAppendixA.py" which will parse a Word (.docx) version of Appendix A [Open AppendixA.doc in Word and Save As Word Document (*.docx)]

NOTE: "parseAppendixA.py" has some specific code for dealing with the particular way the HL7 Version 2.4 AppendixA.doc was published.
(miss-merged columns and typos in HL7 Table 0458 where some OCE edit codes have a trailing '.') You may need to edit this code to deal with any similar issues in your version of HL7. You can enable debug (with the "-v 4" command line option) and you can get the log messages saved to a file for review. The log file will contain the top 20 rows for each table, as it was extracted from Word, as it was before being output to Excel.

#### Field, Componenent and Subcomponent Lengths

Later version of the HL7 v2.x standard also defines maximum lengths for data types which can exist in any field, component of subcomponent.
**HL7 Validator** checks for the existance of an Excel workbook called "**data types.xlsx**" in the "Schema Directory".
If this Excel Workbook exists and has a Worksheet name "**data types**" with columns of
"D/T", SEQ", "LEN", "DT", "OPT", "TBL#", "COMPONENT NAME", "COMMENTS" and "SEC.REF.", then the columns "D/T", "SEQ" and "LEN"
will be used to validate the length of any field, component or subcomponent with the matching data type.

#### Value Sets

The pattern Identifier/Description/Coding System occurs frequently in HL7 v2.x messages.
Here the Identifier should be a valid code from the Coding System.
Often the set of valid Identifiers is restricted to a subset of all of the values from the Coding System; a subset or value set.
**HL7 Validator** checks for the existance of an Excel Workbook "**value sets.xlsx**" in the "Schema Directory".
If this Excel Workbook exists and has a Worksheet named "**value sets**" with column of "segment", "group(s)", "field/component", "system", "code" and "description".
This data will be used to check that valid codes have been selected from the specified coding systems.

| group(s) | field/component | system | code | description |
| --- | --- | --- | --- | --- |
| | OBX-3 | LN | 1554-5 | |
| | OBX-3 | LN | 3137-7 | |
| | DG1.4 | I10 | R63.4 | |

Which would mean that "1554-5" would be a valid identifier in field 3, component 1 of any OBX segment, if the "coding system" [OBX-3.3] was specified as "LN". "3137-7" would also be valid, but any other "LN" identifier would be invalid.

The specified Field or Component should be one which has one of the coding data type [CE, CF, CNE, CWE] which have two sets of codings,
with the second set being an alternative coding. **HL7 Validator** will test both coding sets if they both exist.
If, in a specified field/component, the "coding system" is one that does not exist in the file "value sets.xlsx" then no validation is performed;
unknown codes from unknown coding systems are not an error.

The column "group(s)" can be a comma separated list of message structure groups, which lets you specify value set validation for a specific field/component, but only when it occurs within one of the specified message structure groups.

| group | field/component | system | code | description |
| --- | -- | --- | --- | --- |
| ORU_R01.OBSERVATION | OBX-3 | LN | 1554-5 | |

Here, the value set in the OBX-3 field would be validated, but only whe the OBX segment it occured in a ORU_R01.OBSERVATION message structure group.
Inside a message structure group, field/component value set validation, specified for the message structure group, takes precedence over general value set validation.

The option column "description" can contain a pipe delimited (|) list of valid descriptions for the specified code.

**Note:** it may be necessary to configure up more than one instance of **HL7 Validator** - potentially one per interface,
as the LOINC codes acceptable in one interface (e.g. Pathology results) may be different to the set of LOINC codes in another interface (e.g. Radiology reports).
Similarly, an interface may use just a small subset of message types, so you may choose to delete any unused message structure schema definition files.
You may also want to expand the HL7 v2.xml schema specification to include definitions for any local Z-segments.

## Conformance and Business Rules

Sometimes one or more fields, components or subcomponents may need to conform to some specific business rules.

* A field may contain a provider identifier but, for some assigning authorities, the format of that identifier may need to match some business rules.
* If there is a Patient death date, and time, in PID-29, then the Patient death indicator in PID-30 **must** be set to "Y"
* A OBR segment indicating patient consent, must have an acceptable consent value ("withdrawn"/"not withdrawn")
* The last segment in an OBR/OBX group **must** be a display segment

To support conformance testing **HL7 Validator** uses Business Rules
created using DMN (Decision Model Notation).

**HL7 Validator** checks for the existance of two Excel Workbooks, "**Business Rules.xlsx**" and "**Business Rules DMN.xlsx**" in the "Schema Directory".

"**Business Rules.xlsx**" defines the triggers for when the conformance of data will be checked and the business rule(s) that will be used to check that conformance. Rules can be triggered for fields, segments or the message as a whole.

"**Busienss Rules DMN.xlsx**" must be a valid Decision Model Notation workbook, compatible with the **pyDMNrules** Python module - an implementation of the Object Managment Group's (OMG) Decision Model Notation (DMN) specification. DMN require the business rules to be written in DMN's FEEL (Friendly Enough Expression Language) language.

Every Business Rule must have a name. If the Business Rule name starts with the character "#", then that rule will be considered disabled and will not be run; you don't have to delete a rule that you do not want to run, you can just comment it out in **Business Rules.xlsx". For **Datatype Business Rules**, **Field Business Rules**, **Segment Business Rules** and **XPath Business Rules** [see below], that rule name is the linkage between rule parameters in **Business Rules.xlsx** and the matching decision table defined in **Business Rules DMN.xlsx**. The Decision Table on the Decision Worksheet in **Business Rules DMN.xlsx** is that linkage.

**HL7Validator** will use the "**Business Rules DMN.xslx**" workbook
to create a **Rules Engine**; something that data can be passed through in order to check if it complies with the defined **Busines Rules**.

### Datatype Business Rules

Datatype Business rules are general rules that apply to all instances of a datatype, such as identifiers must have a coding system, patients and practitioners must have a name, organizations must have a street address. The Excel Workbook, "**Busisness Rules.xlsx**", must contain one Worksheet named "**datatype rules**" with the headings "datatype", "group(s)", "segment(s)" and "rule". These rules are executed after the data in a field or component have been validated, if the datatype of that field or component has a defined Datatype Business Rule. "group(s)", if specified, must be a comma listed set of one or more message structure groups and can be used to restrict testing to only instances of this datatype in segments in one or more of the message structure groups named in the "group(s)" column. The message structure is a message structure group and can be used to restrict rules to specific message types (e.g. ORM_O01 for orders and ORU_R01 for results). "segment(s)", if specified, must be a list of segment codes and can be used to restrict testing to only instances of this datatype in the specified segment(s).

| datatype | group(s) | segment(s) | rule |
| --- | --- | --- | --- | --- |
| CE | ORU_R01 | OBX | Check CE Coding System |
| CE | ORU_R01 | OBX | Check LOINC |

There can be multiple rules for each datatype; the first might check that identifiers have coding systems whilst the second check the identifier and the alternate identifier to ensure that any LOINC code is the identifier and not the alternate identifier.

For **Datatype Business Rules**, **HL7 Validator** will test each repetition of a field and each instance of a component, if that field or component islisted in the "datatype rules" Worksheet in the "**Business Rules.xlsx**" Workbook, by calling the **Rules Engine**. The data passed to the **Rules Engine** is a dictionary where the keys are the datatype name and the values are the data in the associated component/subcomponent.
Only components/subcomponents present and defined in the **Rules Engine** **Glossary** will be populated as input data for the **Rules Engine**.

For instance, if we have an OBX-3 field of  
|2951-2^Sodium^LN^Na^^PLS|  
and a **Rules Engine** rule called 'Check CE Coding System' that that identifiers have code system (only interested in the identifier [CE.1], the assiging authority [CE.3], the alternate identifier [CE.4] and the alternate coding system [CE.6], so only CE.1, CE.3, CE.4 and CE.6 will be defined in the **Glossary**), then the data passed to the associated **Datatype Business Rule** would be

    data = {}
    data["Rule"] = "Check CE Coding System"
    data["CE.1"] = "2951-2"
    data["CE.3"] = "LN"
    data["CE.4"] = "Na"
    data["CE.6"] = "PLS"
    (status, newData) = dmnRules.decide(data)

If a field datatype has component with subcomponents, then the subcomponents will be named as extensions of the component, not as separate datatypes. And the component which has subcomponents will be encoded as well, as a component without any splitting of the data, which is useful for testing situations where the subcomponents should not be present.

For instance, if we had an XAD field of  
|14th Floor&Paterson St&50^50 Paterson St^Coorparoo^QLD^4151|  
and a **Rules Engine** rule called 'Check Address' for checking the XAD datatype [which has subcomponent in the first component] then data passed to the **Datatype Business Rule** would be

    data = {}
    data["Rule"] = "Check Address"
    data["XAD.1"] = "14th Floor&Paterson St&50"
    data["XAD.1.1"] = "14th Floor"
    data["XAD.1.2"] = "Paterson St"
    data["XAD.1.3"] = "50"
    data["XAD.2"] = "50 Paterson St"
    data["XAD.3"] = "Coorparoo"
    data["XAD.4"] = "QLD"
    data["XAD.5"] = "4151"
    (status, newData) = dmnRules.decide(data)

NOTE: Datatypes with definitions in the HL7 Standard are already tested for structural validity as per the table below.

| Datatype | Structural Test | Regex expression |
| --- | --- | --- |
| CF/TX | Check for invalid escape sequences | \\\\(?![HNSTRE]\\\\\|X[0-9A-Fa-f]+\\\\\|Z[^\\\\]*\\\\\|C[0-9A-Fa-f]{4}\\\\\|M[0-9A-Fa-f]{4}\\\\\|M[0-9A-Fa-f]{6}\\\\) |
| DT | Valid Date and parse with dateutil.parser | ^[12]\d{3}((0[1-9]\|1[0-2])(0[1-9]\|[12]\d\|3[01])?)?\$ |
| ED | Validly encoded ED data | |
| FT | Check for invalid escape sequences | \\\\(?![HNSTRE]\\\\\|X[0-9A-Fa-f]+\\\\\|Z[^\\\\]*\\\\\|C[0-9A-Fa-f]{4}\\\\\|M[0-9A-Fa-f]{4}\\\\\|M[0-9A-Fa-f]{6}\\\\\|\\.sp([\d]+)?\\\\\|\\.(br\|ce\|fi\|nf)\\\\\|\\.\(in\|ti)[-+]?[\\d]+\\\\\|\\.sk\\d+\\\\) |
| | Also check for indents after a printable character | (?<!(^\|\\\.br\\\|\\\.sp([\\d]+)?\\\\)(\\\.(br\|ce\|fi\|nf)\\\\\|\\\.\(in\|ti)[-+]?[\\d]+\\\\)*)\\\.\(in\|ti)[-+]?[\\d]+\\\\ |
| NM | Check for correctly formatted numeric | ^[-+]?\\d+(\\.\\d*)?\$ |
| RI | Check for legally formatted time interval | ^\([01]\\d\|2[0-4])[0-5]\\d(,\([01]\\d\|2[0-4])[0-5]\\d)*\$ |
| SI | Check for correctly formatted Sequence Identifier | ^\\d{1,4}\$ |
| SN | Check for valid comparitor | |
| | Check for correctly formatted separator/suffix | |
| ST | Check for invalid escape sequences | \\\\(?![STRE]\\\\\|C[0-9A-Fa-f]{4}\\\\\|M[0-9A-Fa-f]{4}\\\\\|M[0-9A-Fa-f]{6}\\\\) |
| TM | Valid Time | ^([01]\\d\|2[0-4])([0-5]\\d([0-5]\\d(\\.\\d{1,4})?)?)?([-+]\(0\\d\|1[0-3])[0-5]\\d)?\$ |
| TN/XTN | Correctly formatted telephone number* | ^(\\\d\\d)?((\\d{3}))?\\d{3}-\\d{4}(X\\d{4})?(B\\d{4})?(C.*)?\$ |
| TS | Valid Date and Time, plus parse with dateutil.parser | ^[12]\\d{3}((0[1-9]\|1[0-2])((0[1-9]\|[12]\\d\|3[01])(([01]\\d\|2[0-4])([0-5]\\d([0-5]\\d(\\.\\d{1,4})?)?)?)?)?)?([-+]\(0\\d\|1[0-3])[0-5]\\d)?\$ |
| | Also checks any precision | ^[YLDMHS]$ |

* This is the format defined in the HL7 Standard. It is possible that it is not correct for your region. **HL7 Validator** has a command line option [-T telephonePatter|--telephonePattern=telephonePattern] which lets you specify an alternate regular expression for the pattern of you local phone numbers.

### Field Business Rules

Field Business Rules test one instance, of one field, in one segment and are executed after all of the data in the field and all repetition of that field, has been validated. The Excel Workbook, "**Business Rules.xlsx**", must contain one Worksheet named "**field rules**" with the headings "field(s)", "group(s)", "rule", "type" and "count". "field(s)" is a comma separated list of message fields. The rules for each field that will be applied to each repetition of each specified field. "group(s)", if specified, must be a comma listed set of one or more message structure groups and can be used to restrict testing to only instances of field(s) in segments in one or more of the message structure groups named in the "group(s)" column. The message structure **is a message structure group** and can be used to restrict rules to specific message types (e.g. ORM_O01 for orders and ORU_R01 for results). There may be different business rules for a specific ORB field in a laboratory order and different rules for the same OBR field in a pharmacy order.

| field(s) | group(s) | rule | type | count |
| --- | --- | --- | --- | --- |
| PV1-8 | | ProvIDtest | all | |

The "type" must be "all", "min" or "max".

* Rules of type "all" will fail testing if **any** repeat of a field fails the business rule and every failure will be reported.
* Rules of type "min" and "max" require a mandatory "count" and will not fail for any specific repetition, but rather a count of successes will be maintained. After all repetitions of a field have been tested, the rule will fail if less than "min" or more than "max" repetitions pass the business rule and that failure will be reported.

There can be multiple rules for each field or set of fields; for instance the rule "ProvIDtest", of type "all" may test all Provider identifiers for a specific Assigning Authority and pass or fail each Provider ID with that Assigning Authority, depending upon whether or not the Provider ID passes a set of valid data tests. The default, for any Provider ID with another Assigning Authority would be pass, so that those other Provider IDs would not reported as errors.

You could then create a second buisness rule (ProvIDcount) with the same DMN logic as "ProvIDtest", but where the default, for any Provider ID with another Assigning Authority would be fail. You could then test that there is one, and only one, Provider Identifier, with this Assigning Authority, with a valid Provider ID, amongst all the repeitions of the field(s) by adding two more rules to "**Business Rules.xlsx**" on the "field rules" worksheet, both for fields containing Provider IDS;  one" with "rule" "ProvIDcount", "type" "min" and "count" "1"; the other with "rule" "ProvIDcount", "type", "max" and "count" "1". The conformance test here assumes that a provider can be identified multiple times in a field, with multiple different identifiers, but that they must be identified exactly once with the officially sanctioned identifier.

| field(s) | group(s) | rule | type | count |
| --- | --- | --- | --- | --- |
| PV1-7,PV1-8,PV1-9,PV1-17,ORC-10,ORC-11,ORC-12,ORC-19,OBR-10,OBR-16 | | ProvIDtest | all | |
| PV1-7,PV1-17,ORC-12,OBR-16 | ORU_R01,ORM_O01 | ProvIDcount | min | 1 |
| PV1-7,PV1-17,ORC-12,OBR-16 | ORU_R01,ORM_O01 | ProvIDcount | max | 1 |

This checks that there are no Attending Doctors, Referring Doctors, Consulting Doctor, Admitting Doctor, Entering Practitioner, Verified by Practitioner, Ordering Provider (in ORC), Action By Provider, Collection Identifier Provider or Ordering Provider (in OBR) that has an invalid Provider ID. It also check that there is exactly one Attending Doctor, Admitting Doctor, one Ordering Provider (in ORC) and one Ordering Provider (in OBR) in Lab orders and Lab results.

Note: In order to test that there is at least one valid Ordering Provider in either ORC-12 **or** OBR-16 you would need to create an **XPath Business Rule** (see below).

Note: a business rule can invoke another business rule. So, ProvIDcount could fail all Provider identifiers that don't have a specific Assigning Authrority, but then just **Execute** ProvIDtest for all Provider IDs that do have that Assigning Authority. That way, you are testing and counting only the occurances of a Provider ID that has that specific Assigning Authority.

For **Field Business Rules**, **HL7 Validator** will test each repetition of any field listed in the "field rules" Worksheet in the "**Business Rules.xlsx**" Workbook, by calling the **Rules Engine**. The data passed to the **Rules Engine** is a dictionary where the keys are the field name or component name or subcomponent name and the values are the data in the associated field/component/subcomponent in this repetition.
Only field/components/subcomponents present in this repetition of the field and defined in the **Rules Engine** **Glossary** will be populated as input data for the **Rules Engine**.

**Field Business Rules** can also leverage the logic for **Datatype Business Rules** as the data will also be also be passed to the **Rules Engine** with the encoding applicable to the field datatype, as per the **Datatype Business Rules** encoding described above. Hence, a **Field Business Rule** could **Execute** a **Datatype Business Rule** as part of the testing of the field(s).

For instance, if we have a PV1-8 field of  
|113467AL^SMITH^JOHN^^^DR^^^AUSHICPR|  
and a Rules Engine rule called 'ProvIDtest' that tests provider identifiers (only interested in the identifier and the assiging authority,
so only PV1-8.1, PV1-8.9, XCN.1, XCN.9 and XCN.9.1 will be defined in the **Glossary**), then the data passed to the associated **Field Business Rule** would be

    data = {}
    data["Rule"] = "providerID"
    data["PV1-8.1"] = "113467AL"
    data["XCN.1"] = "113467AL"
    data["PV1-8.9"] = "AUSHICPR"
    data["XCN.9"] = "AUSHICPR"
    data["XCN.9.1"] = "AUSHICPR"
    (status, newData) = dmnRules.decide(data)

All the Rules Decision Tables in the associated **Rules Engine** must return a single boolean value of "Passed" which must be set to **True** or **False** (SFEEL value 'true' and 'false'),
and a string value of "Reason" containing the reason that the input did/did not pass this test. If the test failed then the the Reason should start with ERROR:, WARNING: or COMMENT: to indicate the severity of the failure.

### Segment Businees Rules

Segment Business Rules test each instance of a segment as a whole, passing all the field, components and subcompoonents. **Segment Business Rules** enable the testing of the relationships between the fields in each instance of the specified segment. The "**Business Rules.xlsx**" Excel Workbook, must contain a Worksheet called "segment rules" with the headings "segment", "group(s)", "rule", "repFields", "type" and "count".
These are rules that will be applied to each insance of the segment, after field validation of all the field in the segment, to ensure combinations of fields within the segment meet some busienss rule. "group(s)", if specified, must be a comma separted list of one or more message structure groups and can used to be restrict testing to only instances of this segment in one or more of the message structure groups named in the "group(s)" column. The message structure **is a message structure group** and can be used to restrict rules to specific message types (e.g. ORM_O01 for orders and ORU_R01 for results).

| segment | group(s) | rule | repFields | type | count |
| --- | --- | --- | --- | --- | --- |
| OBX | ORU_R01.OBSERVATION | SNOMED_CT | OBX-3,OBX-5 | all | |

This could test that OBX-5 is only the SNOMED_CT concepts of "Consent withdrawn" or "Consent not withdrawn" when OBX-3 is the SNOMED_CT concept of "Upload Consent".

Note: A segment can be tested more than once, for the same rule, if multiple segment groups are specified and some segment groups are contained within other segment groups. For instance  
| OBX | ORU_R01,ORU_R01.ORDER_OBSERVATION,ORU_R01.OBSERVATION |  
will test the OBX segment three time as ORU_R01.OBSERVATION is contained within ORU_R01.ORDER_OBSERVATION and both are in the ORU_R01 message structure.

The "type" can be "min" or "max" or blank.

* Rules without a type will fail testing if **any** instance of the segment fails the business rule and every failure will be reported.
* Rules of type "min" and "max" require a mandatory "count" and will not fail for any specific instance of the segment, but rather a count of successes will be maintained for instances of the segment, within each group (if any groups are specified). The rule will fail if, after all instances of the segment, within each group (if any groups are specified) have been tested, less than "min" or more than "max" instances of this segment passed the business rule and that failure will be reported.

NOTE: You can have different rules for inner segment groups and outer segment groups, for the same segment.

There can be multiple rules for each segment, so you could check that there we don't have both SNOMED_CT codes in OBX-5 in two different OBX segments.

| segment | group(s) | rule | repFields | type | count |
| --- | --- | --- | --- | --- | --- |
| OBX | ORU_R01.OBSERVATION | SNOMED_CT | OBX-3,OBX-5 | all | |
| OBX | ORU_R01.OBSERVATION | SNOMED_CTcount | OBX-3,OBX-5 | max | 1 |

The data passed to the **Rules Engine** is a dictionary
where the keys are the field names or component names or subcomponent names and the values are the data in the associated fields/components/subcomponents.

Only fields/components/subcomponent present in the segment and defined in the **Rules Engine** **Glossary** will be populated as **Rules Engine** input data.
Any field which does not repeat will be passed as a value. However, if a field can repeat then the field data will be a **DMN List** matching the field/component/subcomponent values from the repetitions.

DMN has a built-in FEEL function "contains()" to determine if a value exists in a List. And you can chose to test just a specific List value. However, the business rule may be easier to write and easier to implement, if the segment was tested once for each "repetition" of a repeating field or sets of repetitions for multiple repeating fields. To support this, the "repeating" fields can be listed, as a comma separated list of fields, in the "repFields" column. The number of repetitions in the first field in "repFields" will determine the number of times the segment data is tested using the **Rules Engine**.
An additional parameter (**Repeat Number**) will be passed to the **Rules Engine**, identifying the repetition being tested. This can be used for diagnostic messages returned from the **Rules Engine**.

NOTE: If "min" or "max" is specified, then the set of tests, for the repeating field, is considered **one test** of the **Segment Business Rule**; if any one repetition passes then this **Segment Business Rule** passes for this instance of this segment.

NOTE: The first field doesn't have to be a repeating field. In the above example, OBX-3 can't repeat, so the business rules will be run only once, with values from OBX-3 and values from the first repeat of OBX-5.

NOTE: Repeating fields are usually easier to test using a **Field Business Rule** (see above) or an **XPath Business Rule**
(see below) where each repetition of the field will be passed through the **Rules Engine** with all the matching data.

NOTE: **Segment Business Rules** cannot leverage any **Datatype Business Rules** as no datatype encoding of the data is performed.

Hence, if we have an OBX segment of  
OBX|1|CE|2951-2^Sodium^LN^Na^^PLS||138|mmol/L^mmol/L^UCUM|137-145||||F  
and a **Rules Engine** that tests Unit for LOINC codes with numeric results (only intested in OBX-2, OBX-3.1, OBX-3.3, OBX-6.1, OBX-6.3), then the data passed to the **Rules Engine** will

    data = {}
    data["Rule"] = "LOINCunits"
    data["OBX-2"] = "NM"
    data["OBX-3.1"] = "2951-2"
    data["OBX-3.3"] = "LN"
    data["OBX-6.1"] = "mmol/L"
    data["OBX-6.3"] = "UCUM"
    (status, newData) = dmnRules.decide(data)

The "LOINCunits" Business rules would need to check that OBX-2 is "NM", check that OBX-3.3 is "LN" and check that OBX-6.3 is "UCUM".
Then it would check combinations of OBX-3.1 and OBX-6.1, looking for a match.

NOTE: To checks that the LOINC number is a correctly constructed number you would normally use a **value set** (see above). If you can't use a **value set** then you may be able to use an **XPath Business Rule** (see below). For instance, an **XPath Business Rule** might test that all OBX-3 values are in a subset of LOINC, constrained by the SNOMED_CT code in OBR-4.

All the Rules Tables in the associated **Rules Engine** must return a single boolean value of **Passed** which must be set to **True** or **False** (SFEEL value 'true' and 'false'),
and a string value of "Reason" containing the reason that the input data did/dud not pass this business rule. If the input did not pass this buisness rule then the the Reason should start with ERROR:, WARNING: or COMMENT: to indicate the severity of the failure.

### XPATH Business Rules

**HL7 Validator** parses a message using the matching v2.xml Schema. As by product, it creates the matching HL7 v2.xml message
which you will find in the output folder. To facilitate complex testing rules, it is possible to pass the **Rules Engine** multiple fields/components/subcomponents that have been located in the message, using a set of XPATH expressions. **HL7 Validator** uses the Python **lxml** module to find the matching data in the message.

The "**Business Rules.xlsx**" Excel Workbook, must contain a Worksheet called "XPath rules" with the headings "rule", "rule path", "rule type", "rule count", "field path", "field type", "field count" and "linked" followed by a sequence of columns with the headed "xpath". The first column with a heading other than "xpath" (e.g. "Comment"/"Description"/"Annotation") will define the maximum number of "xpath" definitions. For each"rule", the first "xpath" column that is empty or blank, will define the actual number of "xpath"s that apply to that specific rule.

These **XPath Business Rules** are rules that will be applied after every segment, field, component and subcomponent has been validated and tested with the **Field Busieness Rules** and **Segment Business Rules**.

* **rule path** must be an absolute path to either '/' or a message structure group or a segment. e.g. "//OBR" to retieve all the "OBR" segments. You can use **XPath expressions** to constrain this to a specific set of OBR segements. e.g. "//OBR[OBR.1='1']" to retrieve all OBR segments with a Set ID of "1".  
* **field path** must be a path to a field. It can be relative to **rule path** or it can be an asolute path.  You can use **XPath expressions** to constrain this to a specific fields. e.g. "../OBX.3[CE.3[text()='LN']]" to retrieve all OBX-3 fields which have a LOINC code.

NOTE: HL7 v2.xml uses "seg" as the XML tag for segments and "seg.n" as the XML tag for fields. XPath expression must follow the HL7 v2.xml naming conventions. Hence //OBR/OBR.1 is all OBR-1 fields in all OBR segments. Components and subcomponents use "datatype.n" for tags. Hence, ERR-1.4.1, with a value of "130", is encoded in the HL7 v2.xml message as  
"\<ERR\>\<ERR.1\>\<ELD.4\>\<CE.1\>130\</CE.1\>\</ELD.4\>\</ERR.1\>\</ERR\>"  
as the ERR.1 field has the datatype of "ELD" and the first subcomponent of the fourth ELD component had the datatype of CE. The XPath to this value would be '//ERR/ERR.1/ELD.4/CE.1'.

The subsequent **XPath**s can be absolute or a relative path from **field path**. e.g. "../OBX.5" to retrieve the data from the OBX-5 field in this OBX segment (**field path** must be a path to a field in an OBX segment).

**HL7 Validator** assumes that **rule path** will return a set of nodes; multiple instances of a message structure group, or multiple instance of a segment and that the **field path** will return a set of nodes, possibly relative to each **root path** node, which may be different for each of the nodes returned by the **root path**.

Each **rule node** from the **rule path** will be tested separately. For each **rule node**, **HL7 Validator** will fetch a set of **field nodes**, using the **field path**. Each **field node** will be tested for each **root node**; **HL7 Validator** will run a **rule** test for each **rule node**/**field node** pair.

The action taken, and failures reported will depend upon the "**rule type**" and "**field type**" for this rule. The "**rule type**", if specified, must be "min" or "max", which controls the error reported after all **rule node**/**field node** pairs have been tested.

* Rules with a **rule type** of type "min" and "max" require a mandatory **rule count**. **HL7 Validator** will keep a count of successful **rule path**/**field path** tests. After all **rule path**/**field path** pairs have been tested. The **rule** will fail, and the failure will be reported, if **rule type** is "min" and the count of successes is less than **rule count**. The **rule** will also fail, and the failure will be reported, if **rule type** is "max" and more than **rule count** tests have passed the business rule.

**field type** effects how how any success/failures will be reported for each **root path**/**field path** pair of all the **field path**s for each specific **root path**. **field type** must be "min", "max" or "all".

* Rules with a **field type** of "all" will report every failure.
* Rules with a **field type** of type "min" and "max" require a mandatory **field count** and will not fail for any specific repetition, but rather a count of successes will be maintained for each **root path**. After all repetitions for a specific **root path** have been tested the count of successes will be checked. The **rule** will fail for this **root path** node, and that failure will be reported, if **field type** is "min" and the count of successe is less than **field count**. The rule will also fail for this **root path**, and that failure will be reported, if **field type** is "max" and more than **field count** repetitions have passed the business rule.

#### Subsequent **xpath**s and **linked**

Each of the subsequent **xpath** columns will be a path to a field. Potentially, these can be different fields in different segments, but the field may have the same field name. You may have a **field path** that selects each OBX-3 field, with a specific value in OBX-3.1 and need to test that against the value in OBX-3.1 in the next OBX segment in this OBR/OBX group. The **Rules Engine** would need to be passed two sets of "OBX-3.1" data and would need to know which is which. To facilitate this, all names for **xpath** column fields/components/subcomponents are prefixed with a letter; "a" for the first **xpath**, "b" for the second **xpath** and so on. Hence, there is a limit of 26 **xpath** columns. The data passed to the **Rules Engine** for such a test may look like

    data = {}
    data["Rule"] = "pairs"
    data["OBX-2"] = ["CE"]
    data["aOBX-3.1"] = ["2951-2"]
    data["aOBX-3.3"] = ["LN"]
    data["bOBX-2"] = ["CE"]
    data["cOBX-3.1"] = ["2951-2_extra"]
    data["cOBX-3.3"] = ["L"]
    (status, newData) = dmnRules.decide(data)

NOTE: Only field/component/subcomponent data for fields/components/subcomponents in the DMN **Glossary** (see below) will need be passed to the **Rules Engine** and that additional "aOBX-3", "bOBX-2" and "cOBX-3" definitions will be required in the "OBX" Business Concept group.

NOTE: the data fetched from each **xpath** field/component/subcomponent is passed as a DMN List because each **xpath** can return multiple nodes, even if only a single node is fetched. This can be modified by setting the **linked** column to "y" [see below].

For each **rule path**/**field path** test the data for the **field path** will be the data from a single instance of that field. It will be passed to the **Rules Engine** using the same naming and construction convention outlined in **Field Business Rules** above. For the subsequent **xpath**s the name is changed and the data is passed as DMN Lists. DMN has functions for testing lists ("list contains()" and "index of()") and it is possible to construct DMN Decision Tables that iterate over a List. However, this complexity may not reflect the underlying test you are trying to perform. There may be a relationship between each **field node** and the matching **xpath node**s. You may wish to test the first **field node** with the first node in each **xpath** list and the second **field node** with the second node in each **xpath** list. You can enforce this by setting **linked** to "y".

When **linked** is set to "y" all **xpath** field/component/subcomponent data is passed a single values, not in a DMN List. This can simplify the writing of the matching DMN rule (or Decision Tables), but possibly at the expense of not testing all the data.
An additional parameter (**Repeat Number**) will be passed to the **Rules Engine**, identifying the repetition being tested. This can be used in diagnostic messages returned from the **Rules Engine**.

Setting **linked** to "y" makes sense when all the **xpath** expressions lead to fields that don't repeat, or where you only want to test the first repetition. For instance, you may want to test that all numeric data has the correct units for each test code. Your **XPath Business Rule** may look like

| rule | rule path | rule type | rule count | field path | field type | field count | linked | xpath | xpath |
| checkUnits | / | | | //OBX.2[text() = "NM"] | all | | y | ../OBX.3 | ../OBX.6 |

And the data passed to the **Rules Engine** could look like

    data = {}
    data["Rule"] = "checkUnits"
    data["OBX-2"] = "NM"
    data["aOBX-3.1"] = "2951-2"
    data["aOBX-3.3"] = "LN"
    data["bOBX-6"] = "mmol/L"
    (status, newData) = dmnRules.decide(data)

### Parser Business Rules

Sometime the data in a field/component/subcomponent must match some grammer or lexical structure.
For instance, if you use UCUM for units of measurement, then UCUM code is actually a UCUM expression, which has to comply with the UCUM grammer for units of measurement. Similarly, the data on OBX-5 may be a Base64 encoded HTML document. Once decoded, that document must be valid HTML, or perhaps XHTML. And the conformance profile may ban certain HTML tags.

**Parser Business Rules** are different to all the other Business Rules. **Parser Business Rules** are part of the code. If you need another parser then you have to edit the code. Simiarly, the tests that are valid for each parser are part of the code. If you want an additional test for an existing parser then you have to edit the code. Similarly, no field/component/subcomponent definition is required in the "Glossary" in **Business Rules DMN.xlsx** as the data fetched for **Paser Business Rules** testing will not be passed to the **Rules Engine**.

**Parser Business Rules** are run after all the **XPath Business Rules** have been run.
The "**Business Rules.xlsx**" Excel Workbook, must contain a Worksheet called "parser rules" with the headings "rule", "parser", "test(s)", "isBase64" and "xpath".
These are not **DMN** rules, so the column "rule" has no functional value, but can be used to document the conformance profile point being tested.
The "parser" must be one of the defined parser from the table below. "test(s)" is a comma separated list of parser test to perform on the data.
"isBase64" must be "Y" if the data should be Base64 encoded. **HL7 Validator** will attempt to decode the data from Base64 encoding, if "isBase64" is "Y", before passing the data to the specified parser.

Each test must be a valid test for the specified parser taken from the table below. If the first character of a test is "#" then that test will be deemed to have been temporarily disabled and won't be run.

"xpath" must be an absolute XPath from the root of the HL7 v2.xml message which may return multiple instances of data, each of which will be tested.
The "xpath" expression is will probably be complex, with conditions to constrain the selection to data that is relevant for the specified parser test(s)

| rule | parser | test(s) | isBase64 | xpath |
| --- | --- | --- | --- |
| Check UCUM | UCUM | isValid | | //OBX.6/CE.1[../CE.3[text() = "UCUM"]] |

#### The UCUM Parser

The UCUM parser uses the Python 'ucumvert' module to test if the data is a valid UCUM expression.
Is is usually used to test the Units of Measurement in OBX-6.
It is a simple validity tester and does not test that the UCUM expression is the correct expression for the test code in OBX-3.
For that, you would need fixed relationship between the test code and the unit of measurement string and a **Segment Business Rule** [see above].

#### The FT Parser

**HL7 Validator** validates FT data according to the rules in Chapter 2 of the HL7 Standard if the datatype is "FT".
However, it does pass if all the escape sequences are validly constructed. Your conformance profile may exclude some escape sequences
such as hexidecimal data or locally defined escape sequences. The FT parser is not so much a parser as a set of validation tests on the FT data itself.

#### The XHTML Parser

**HL7 Validator** uses the Python 'lxml' module to build the HL7 v2.xml message and to do any **XHTML Parser** testing.
XML parsing can be either 'strict' or somewhat relaxed, with the parser fixing easily identified minor errors.
The **XHTML Parser** can do either. One of the **XHTML Parer** tests is **XHTMLstrict**. If this test is in the list of tests the it will be performed first, and if it fails no other **XHTML Parser** tests will be run on the selected text.

**HL7 Validator** uses the 'lxml' module to do the strict parsing, but the Python module BeautifulSoup to parse the selected test before performing any of the other tests.

#### The PDF Parser

**HL7 Validator** uses the Python "pypdf" module to do any **PDF Parser** testing.

#### The Defined Parsers and Tests

| Parser | Tests | Description |
| --- | --- | --- |
| UCUM | isValid | Check that a UCUM expression is valid |
| FT | noX | Fail if \\Xdddd...\\ in FT data |
| | noZ | Fail if \\Zdddd...\\ in FT data |
| | noCE | Fail if \\.ce\\ in FT data |
| | noRepeats | Fail if XML element containing FT data repeats |
| | noC | Fail if \\Cxxyy\\ in FT data |
| | noM | Fail if \\Mxxyy\\ or \\Mxxyyzz\\ in FT data |
| XHTML | XHTMLstrict | Check that the XHTML text is strictly correct |
| | noHTTP | Check that no tags that have a href starting with http:// |
| | noExternalCSS | Check that there are no \<link\> tags with ' type="text/css" and a href starting with https:// |
| | noScripts | Check that there are no \<script\> tags |
| | noBase | Check that there are no \<base\> tags |
| | noLink | Check that there are no \<link\> tags |
| | noXlink | Check that there are no \<xlink\> tags |
| | noFrame | Check that there are no \<frame\> tags |
| | noIframe | Check that there are no \<iframe\> tags |
| | noForm | Check that there are no \<form\> tags |
| | noObject | Check that there are no \<object\> tags |
| | noScripts | Check that there are no \<script\> tags |
| | coreDisplay | Check that there is a \<div\> tag with ' class="reportDisplay" ' |
| | OBXimages | \<image\> tags must have a "src" of "hl7v2://OBX.\<setID\> |
| PDF | PDFstrict | Check that the PDF document is strictly compliant with the header version |
| | versionPDF/A-1b | Check that the header version is "PDF/A-1b" |
| | allFontsEmbedded | Check that all the used fonts are embedded in the document |
| | noComments | Checks that there are no comments (annotations) in the document |
| | canPrint | Check that the document can be printed |
| | canCopy | Check that the document can be copied |
| RTF | wellFormed | Check that RTF starts with \{\\rtf and had balanced opening and closing clurly bracies |
| | noNesting | Check that there are no nested tables |
| | noOLE | Check that there are no Object Linking or Embedding object |
| | noEmbeddedFonts | Check that there are no embedded fonts |
| | noShapes | Check that there are no shapes/other drawing objects |
| | noSmartTags | Check that there are no smart tags |
| | noChangeTracking | Check that there are no change tracking markup or comments |
| | noSectionLayout | Check that there is no section specific page layout |

## External Business Rules

**External Business Rules** let **HL7 Validator** validate data, using external service such as a FHIR Provider Directory service, or a Healthcare Identifiers Patient Search service. **External Business Rules**, like **Parser Business Rules** are different to all the DMN based Business Rules. **External Business Rules** are part of the code. If you need access another service then you have to edit the code. If you need to access an existing **External Buisness Rule** service, but by another method, then you will have to edit the code.  Similarly, no field/component/subcomponent definition is required in the "Glossary" in **Business Rules DMN.xlsx** as the data fetched for **External Business Rules** testing will not be passed to the **Rules Engine**.

**Externa Business Rules** are run after all the **Parser Business Rules** have been run.
The "**Business Rules.xlsx**" Excel Workbook, must contain a Worksheet called "external rules" with the headings "rule", "service", "username", "password", "APIkey", "URL" followed by a sequence of columns with the headed "xpath". The first column with a heading other than "xpath" (e.g. "Comment"/"Description"/"Annotation") will define the maximum number of "xpath" definitions. For each"rule", the first "xpath" column that is empty or blank, will define the actual number of "xpath"s that apply to that specific rule.

These are not **DMN** rules, so the column "rule" has no functional value, but will be used to document the conformance profile point being tested.
The "service" must be one of the defined services from the table below. The "username", "password" and "APIkey" columns can be used to configure the security tokens required to access the service. However, you may want to leave these columns blank, and hard code these in **hl7Validator.py** for security reasons.
[They can be configured for each service and are the first things defined after the import statments at the top of the script.]
The "URL" is the URL for accessing the service, not including any parameters. The "xpath" columns define the parameters for the Service. The first "xpath" must be an absolute **XPath Expression** to a field/component/subcomponent where the data for the first parameter in the set of parameters to be validated, will be found. If this is **XPath Expression** returns multiple matching nodes then the **External Business Rule** will be run for each node in the returned list. Second and subsequent "xpath" expressions can be absolute or relative, but if relative, they will be relative to the current node returned by the first "xpath" expression. Each "xpath" **XPath Expression** must only select data that is suitable for testing by the specified service, for the matching service parameter. The number of "xpath" expressions must match the number of parameters required for each external service.

NOTE: If second and subsequent "xpath" expression return multiple matching nodes, the only the data from the first node in the list will be use as the matching parameter data.

### The Defined External Services

| Service | Description | Parameters |
| --- | --- | --- }
| csiroUCUM | The Australian UCUM validation service [CSIRO Ontology Server (ontoserver)] | "UCUM expression" |
| healthLink | The Australasian HealthLink FHIR Provider Directory service | "edi" |
| IHI | The Australian Healthcare Identifiers Patient Search service (not yet implemented) | |
| HPII | The Australian Healthcare Identifiers Provider Search service (not yet implemented) | |

## Business Rules Definitions

If the Excel Workbook "**Business Rules.xlsx" exists then the Excel Workbook "Business Rules DMN.xlsx" must also exist and it must contain
a Decision Model Notaion (DMN) specification compatible with **pyDMNrules**. **HL7 Validator** will build a **Rules Engine** from the Excel Workbook "**Business Rules DMN.xlsx**".

Each segment, referenced by any Decision Table, should be it's own Business Concept. The variables within a segment Business Concept are normal, HL7 field, component and subcomponent names (unless you are referencing an **xpath** expression [see above]). e.g.

OBX-2  
OBX-3.1  
OBR-15.1.1  

The Attributes of each Variable must be a valid FEEL name, that is unique within each Businesss Concept (segment Code). One way of doing this is to preface the field number with "f", the component number with "c" and the subcomponent number with "s".

| Variable | Business Concept | Attribute |
| --- | --- | --- |
| OBX-2 | OBX | f2 |
| aOBX-2 | | af2 |
| OBX-3.1 | | f3c1 |
| OBR-15.1.1 | OBR | f15c1s1 |

NOTE: the second "OBX-2" definition is there to support an **xpath** expression [see above] that returns an "OBX" field.

The "Decision" table in the DMN specification uses the passed "Rule" to select which Decision Tables to invoke. The names of the rules should be unique across all types of **Business Rules**; you shouldn't have two rules called the same thing when one is testing one set of fields and the other is testing a different set of fields.
