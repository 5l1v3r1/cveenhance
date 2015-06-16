This work is licensed under the MIT License. 
The MIT License (MIT)

Copyright (c) 2015  Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), 
Ben Hermann (STG), Technische Universität Darmstadt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.


The most recent version of this work can be found at https://github.com/stg-tud/cveenhance

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




