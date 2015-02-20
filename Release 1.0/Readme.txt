============ CREATIVE COMMONS LICENSE (CC BY 4.0) ============
This work is licensed under the Creative Commons Attribution 4.0 International License. 
To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 

authors: Technische Universität Darmstadt - Multimedia Communication Lab (KOM), Technische Universität Darmstadt - Software Technology Group (STG)
websites: http://www.kom.tu-darmstadt.de/, http://www.stg.tu-darmstadt.de/
contact: Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), Ben Hermann (STG)
name: CVE Version Information Extractor

===================== USAGE INSTRUCTIONS =====================

To run the programm, restructure.jar, extract.jar and cve.conf are needed. 
Moreover a XML folder with extracted NVD data feeds (Version 2.0) are needed.
You can download these on https://nvd.nist.gov/download.cfm . Please extract
the XML files to an empty folder and enter the path to this folder in the 
cve.conf under "xmlFolder". 
To extract the information you have to initialise the extractor. The 
restructure.jar splits the XML data feeds into seperated files, which will be 
stored in the folder, which is mentioned under "cveFolder" in cve.conf.
After this process, the extraction can be started by running the 
extract.jar. The enhenced datastreams will be stored under "outputFolder",
mentioned ind the cve.conf.

Please make shure, that all folders are correctly entered in cve.conf.
To work with our tool you should execute first the restructure.jar and afterwards the extract.jar.
In the command line you can use the following commands:
java -jar restructure.jar

java -jar extract.jar

If both command are finished without interruption your enhanced CVE files should be in your specified output
folder.


Thank you for your interest in our tool, we hope you enjoyed it.

Best regards,

STG & KOM TU Darmstadt

==================== STANDARD CONFIGURATION ====================

The most important properties are:

# the path to the directory of your downloaded CVE entry files
xmlFolder=..\\DatabaseXMLs\\

# to work with the entries, we need a better representation of the files in XML format
# this is the directory to save our representation
cveFolder=..\\CVEitems\\

# this property should be false and is only used for debugging
testmode=false

# path to output folder of your enhanced files in XML format
outputFolder=..\\CVE-Output\\

The other properties are described in the cve.conf itself.




