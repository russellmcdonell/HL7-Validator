# HL7 Validator

## Version 1.0 - 26-Aug-2026

This is an "alpha" release. It has been tested with two messages, but it tests the expected things and reports the expected errors.

However, it is the first release to incorporate both message validation (using HL7 v2.xml schemas and Appendix A from the relevant published HL7 Standard) **plus** Conformance Profile testing (with conformance rules written in **DMN** (Decision Model Notation - rules as tables in an Excel Workbook).

Copies of HL7 v2.x Standards, which include Appendix A, can be obtained from [HL7 International](https://www.hl7.org/). You can also download the HL7 v2.x XML Schemas from [HL7 International](https://www.hl7.org/).

This release includes a fully worked example using the Australian Diagnostic and Referral Messaging Conformance Profile ([ADRM](https://confluence.hl7.org/spaces/HA/pages/256186163/HL7+AU+Published+Specifications)). The schema/ADRM/xsd folder has modified schemas that match ADRM. The schema/ADRM fold has a modified "Appendix A.xlsx" with changes that match ADRM. And the schema/ADRM folder has "Business Rules.xlsx" and "Business Rules DMN.xlsx" which specify the conformance profile tests required to ensure compliance with ADRM. The file "schema/ADRM/ADRM Conformance.xlsx" is documentation of which conformance points have been implemented.
