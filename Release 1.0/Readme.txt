Usage instructions

Firstly, you have to download the enhancer.jar, extraction.jar, cve.conf and the CVE entry files, which you want to
enhance.

Secondly, you should configure your cve.conf file.

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

To work with our tool you should execute first the extraction.jar and afterwards the enhancer.jar.
In the command line you could use the following commands:
java -jar extraction.jar

java -jar enhancer.jar

If both command are finished without interruption your enhanced CVE files should be in your specified output
folder.


Thank you for your interest in our tool, we hope you enjoyed it.

Best regards,

STG & KOM TU Darmstadt