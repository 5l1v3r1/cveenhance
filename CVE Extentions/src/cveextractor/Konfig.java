package cveextractor;

/*
 * ============ CREATIVE COMMONS LICENSE (CC BY 4.0) ============
 * This work is licensed under the Creative Commons Attribution 4.0 International License. 
 * To view a copy of this license, visit http://creativecommons.org/licenses/by/4.0/. 
 *  
 * authors: Technische Universität Darmstadt - Multimedia Communication Lab (KOM), Technische Universität Darmstadt - Software Technology Group (STG)
 * websites: http://www.kom.tu-darmstadt.de/, http://www.stg.tu-darmstadt.de/
 * contact: Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), Ben Hermann (STG)
 * name: CVE Version Information Extractor
 *
*/


import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

/**
 * >> This class is used to handle configurations  <<
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class Konfig {

// configuration file readout:
	
	static Properties props=new Properties();
	static
	{
		try {
			props.load(new FileReader("cve.conf"));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	// Path to downloaded CVE XML-Backup
	public static final String XmlFolder = props.getProperty("xmlFolder");
	// Path to splitted CVE item folder
	public static final String CveFolder = props.getProperty("cveFolder");
	// Path to CVE splitted subset folder
	public static final String CveSubsetFolder = props.getProperty("cveDump");
	// Data type of CVE XML files
	public static final String Datatype = props.getProperty("datatype");
	// extraction test mode switch
	public static final boolean Testmode = Boolean.valueOf(props.getProperty("testmode"));
	//
	public static final boolean Logging = Boolean.valueOf(props.getProperty("logging"));
	
	// size of subset (number of subset cve items)
	public static final int DumpNumber = Integer.parseInt(props.getProperty("dumpNumber"));
	// time which program should stop and just display a message
	public static final int MessageTime = Integer.parseInt(props.getProperty("messageTime"));
	// output file for extraction results
	public static final String CvePrint = props.getProperty("cvePrint");
		
	public static final int searchdistance=Integer.parseInt(props.getProperty("searchdistance"));
	
	public static final String xmlExtensionTag=props.getProperty("xmlExtensionTag");
	
	public static final String outputFolder=props.getProperty("outputFolder");
	
// keyword lists:
	
	// Min-Element  for version numbers = NumericalWord + Versionkeyword? + NumericalWord*
	public static String[] versionKeywords= {"build", "update", "release", "rc", "version", "v",  "rev", "revision"};
	
	// Min-Element for OS recognition  = osKeyword + [osExtention, NumericalWord]*   
	// OS recognition is not implemented by now
	// Keywords are defined in lowercase letters
	public static String[] osKeywords= {"windows", "linux", "android", "ios", "mac", "symbian", "dos", "ubuntu", "fedora", "google", "unix", "debian", "rhel", "suse", "chrome", "blackberry", "bsd", "os"};

	public static String[] osExctentions= {"os", "red", "hat", "kitkat", "jellybean", "honeycomb", "gingerbread", "cupcake", "froyo", "ice", "creme", "sandwich", "kitkat", "tv", "phone", "xp", "vista", "nt", "server", "embedded", "rt", "chrome", "x", "ce", "mobile", "server", "enterprise"};
	// stopword list
	public static String[] stopWords = {"a", "and", "or", "in", "able", "about", "across", "after", "all", "almost", "also", "am", "among", "an", "any", "are", "as", "at", "be", "because", "been", "but", "by", "can", "cannot", "could", "dear","did","do","does","either","else","ever","every","for","from","get","got","had","has","have","he","her","hers","him","his","how","however","i","if","into","is","it","its","just","least","let","like","likely","may","me","might","most","must","my","neither","no","nor","not","of","off","often","on","only","other","our","own","rather","said","say","says","she","should","since","so","some","than","that","the","their","them","then","there","these","they","this","tis","to","too","twas","us","wants","was","we","were","what","when","where","which","while","who","whom","why","will","with","would","yet","you","your","ain't","aren't","can't","could've","couldn't","didn't","doesn't","don't","hasn't","he'd","he'll","he's","how'd","how'll","how's","i'd","i'll","i'm","i've","isn't","it's","might've","mightn't","must've","mustn't","shan't","she'd","she'll","she's","should've","shouldn't","that'll","that's","there's","they'd","they'll","they're","they've","wasn't","we'd","we'll","we're","weren't","what'd","what's","when'd","when'll","when's","where'd","where'll","where's","who'd","who'll","who's","why'd","why'll","why's","won't","would've","wouldn't","you'd","you'll","you're","you've"};
	// connecting keywords
	public static String[] concatWords = {"and", "&"};

	// seperating keywords
	public static String[] seperatingWord = {"or", "/"};
	
	// comparing keywords
	public static String[] comparingWord = {"than", "as"};
		
	public static String[] seperatingChar = {";", ".", "!", "?", ":"};
	
	public static String[] sentenceEndingChar = {".", "!", "?", ":"};
	// date keywords
    public static String[] dateWords = {"january", "february", "march", "april", "may", "june", "july", "august", "september", "october", "november", "dezember", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dez"};
	
    public static String[] timeWords = {"q1", "q2", "q3", "q4", "winter", "spring", "summer", "autumn"};
    // cue words for software names
	public static String[] softwareNameStartWords = {"in"};
	// cue words for software version (fixed indicator) -> indicator must be placed right before a software version
	public static String[] softwareNameStopWords = {"before"};
	// cue words for software version (not fixed until indicator) -> indicator must be placed behind a software version (e.g. Java 7 and earlier )
	public static String[] softwareVersionEnd ={"earlier", "through", "previous", "lower"};
	// cue words for software version (not fixed starting version)
	public static String[] softwareBeginInd = {"from", "later", "after"};
	// cue words for a software range 
	public static String[] softwareRangeInd= {"between"};
	// string which will be inserted by connecting text snippets
	public static String seperator =" ";
	
	// features a snippet may have
	public static String[] SnippetFeatures = {"comma", "word", "possibleversion", "name", "bigletter", "nottouse", 
		"used", "version", "os", "osext", "stopword", "concatword", "comparingword", "seperator", "namestart", "versionstart", "cuebefore", "cueearlier", "cuebegin", "cuebetween", "logicalend", "logicalstart"};
	
	// logical units which may appear in a text
	public static String[] logicalUnits = {"version", "softwarename", "date", "beforeIndicator", "earlierIndicator", "number"};
	
	public static String[] versionTypes = {"fixedversion", "lastunfixedversion"};
	
	public static String[][] combinationConditions = {{"version", "version"}, {"version", "version", "version"}, {"softwarename", "softwarename"}, {"softwarename", "softwarename", "softwarename"}, {"softwarename", "softwarename", "softwarename", "softwarename"}, {"softwarename", "softwarename", "softwarename", "softwarename", "softwarename"}
	};
	
	
}
