package CveCollector;

public class konfig {
	// Path to downloaded CVE XML-Backup
	public static final String XmlFile = "..\\..\\DatabaseXMLs\\nvdcve-2.0-2014.xml";
	// Path to splitted CVE item folder
	public static final String CveFolder = "..\\..\\CVE-Cases-long\\";
	// Path to CVE splitted subset folder
	public static final String CveDump = "..\\..\\CVE-Dump-long\\";
	// Data type of CVE XML files
	public static final String Datatype = ".xml";
	// extraction test mode switch
	public static final boolean Testmode = true;

	
	// size of subset (number of subset cve items)
	public static final int DumpNumber = 1000;
	// time which program should stop and just display a message
	public static final int MessageTime = 1500;
	// output file for extraction results
	public static final String CvePrint = "..\\..\\CveResult.txt";
	
	// Regex Syntax: 
	// ? = once or never, * = never or unlimited times, + = once oder never
	
	// keyword lists:
	
	// Min-Element  for version numbers = NumericalWord + Versionkeyword? + NumericalWord*
	public static String[] versionKeywords= {"build", "update", "release", "rc", "version", "v",  "rev", "revision"};
	
	// Min-Element for OS recognition  = osKeyword + [osExtention, NumericalWord]*   
	// OS recognition is not implemented by now
	public static String[] osKeywords= {"windows", "linux", "android", "ios", "mac", "symbian", "dos", "ubuntu", "fedora", "google", "unix", "debian", "rhel", "suse", "chrome"};

	public static String[] osExctentions= {"os", "red", "hat", "kitkat", "jellybean", "honeycomb", "gingerbread", "cupcake", "froyo", "ice", "creme", "sandwich", "kitkat", "tv", "phone", "xp", "vista", "nt", "server", "embedded", "rt", "chrome", "x", "enterprise"};
	// stopword list
	public static String[] stopWords = {"a", "and", "or", "in", "able", "about", "across", "after", "all", "almost", "also", "am", "among", "an", "any", "are", "as", "at", "be", "because", "been", "but", "by", "can", "cannot", "could", "dear","did","do","does","either","else","ever","every","for","from","get","got","had","has","have","he","her","hers","him","his","how","however","i","if","into","is","it","its","just","least","let","like","likely","may","me","might","most","must","my","neither","no","nor","not","of","off","often","on","only","other","our","own","rather","said","say","says","she","should","since","so","some","than","that","the","their","them","then","there","these","they","this","tis","to","too","twas","us","wants","was","we","were","what","when","where","which","while","who","whom","why","will","with","would","yet","you","your","ain't","aren't","can't","could've","couldn't","didn't","doesn't","don't","hasn't","he'd","he'll","he's","how'd","how'll","how's","i'd","i'll","i'm","i've","isn't","it's","might've","mightn't","must've","mustn't","shan't","she'd","she'll","she's","should've","shouldn't","that'll","that's","there's","they'd","they'll","they're","they've","wasn't","we'd","we'll","we're","weren't","what'd","what's","when'd","when'll","when's","where'd","where'll","where's","who'd","who'll","who's","why'd","why'll","why's","won't","would've","wouldn't","you'd","you'll","you're","you've"};
	// connecting keywords
	public static String[] concatWords = {"and", "or", ","};
	// cue words for software names
	public static String[] softwareNameStartWords = {"in"};
	// cue words for software versions
	public static String[] softwareNameStopWords = {"before"};
	
	// general structure for software information: 
	// softwareNameStartWord -> SoftwareName -> softwareStopWord -> Min-Element(softwareversion)
	
}
