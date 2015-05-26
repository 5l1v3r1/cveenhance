package tud.cve.extractor;

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
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Vector;

/**
 * >> This class is used to handle configurations. Furthermore it contains word lists. <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class Config {

	// configuration file readout:

	static Properties props = new Properties();
	static {
		try {
			props.load(new FileReader("cve.conf"));
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	// Path to downloaded CVE XML-Backup
	public static final String XML_FOLDER = props.getProperty("xmlFolder");
	// Path to splitted CVE item folder
	public static final String CVE_FOLDER = props.getProperty("cveFolder");
	// Path to CVE splitted subset folder
	public static final String CVE_SUBSET_FOLDER = props.getProperty("cveDump");
	// Data type of CVE XML files
	public static final String DATA_TYPE = props.getProperty("datatype");
	// extraction test mode switch
	public static final boolean TEST_MODE = Boolean.valueOf(props.getProperty("testmode"));
	//
	public static final boolean LOGGING = Boolean.valueOf(props.getProperty("logging"));

	// size of subset (number of subset cve items)
	public static final int DUMP_NUMBER = Integer.parseInt(props.getProperty("dumpNumber"));
	// time which program should stop and just display a message
	public static final int MESSAGE_TIME = Integer.parseInt(props.getProperty("messageTime"));
	// output file for extraction results
	public static final String CVE_PRINT = props.getProperty("cvePrint");

	public static final int SEARCH_DISTANCE = Integer.parseInt(props.getProperty("searchdistance"));

	public static final String XML_EXTENSION_TAG = props.getProperty("xmlExtensionTag");

	public static final String OUTPUT_FOLDER = props.getProperty("outputFolder");

	// keyword lists:

	// Min-Element for version numbers = NumericalWord + Versionkeyword? +
	// NumericalWord*
	public static final HashSet<String> VERION_KEYWORDS = new HashSet<String>(Arrays.asList(new String[] { "build", "update", "release", "rc",
			"version", "v", "rev", "revision" }));

	// Min-Element for OS recognition = osKeyword + [osExtention,
	// NumericalWord]*
	// Keywords are defined in lowercase letters
	public static final HashSet<String> OS_KEYWORDS = new HashSet<String>(Arrays.asList(new String[] { "windows", "linux", "android", "ios", "mac",
			"symbian", "dos", "ubuntu", "fedora", "google", "unix", "debian", "rhel", "suse", "chrome", "blackberry", "bsd", "os" }));

	public static final HashSet<String> OS_EXTENSIONS = new HashSet<String>(Arrays.asList(new String[] { "os", "red", "hat", "kitkat", "jellybean",
			"honeycomb", "gingerbread", "cupcake", "froyo", "ice", "creme", "sandwich", "kitkat", "tv", "phone", "xp", "vista", "nt", "server",
			"embedded", "rt", "chrome", "x", "ce", "mobile", "server", "enterprise" }));
	// stopword list
	public static final HashSet<String> STOP_WORDS = new HashSet<String>(Arrays.asList(new String[] { "a", "and", "or", "in", "able", "about",
			"across", "after", "all", "almost", "also", "am", "among", "an", "any", "are", "as", "at", "be", "because", "been", "but", "by", "can",
			"cannot", "could", "dear", "did", "do", "does", "either", "else", "ever", "every", "for", "from", "get", "got", "had", "has", "have",
			"he", "her", "hers", "him", "his", "how", "however", "i", "if", "into", "is", "it", "its", "just", "least", "let", "like", "likely",
			"may", "me", "might", "most", "must", "my", "neither", "no", "nor", "not", "of", "off", "often", "on", "only", "other", "our", "own",
			"rather", "said", "say", "says", "she", "should", "since", "so", "some", "than", "that", "the", "their", "them", "then", "there",
			"these", "they", "this", "tis", "to", "too", "twas", "us", "wants", "was", "we", "were", "what", "when", "where", "which", "while",
			"who", "whom", "why", "will", "with", "would", "yet", "you", "your", "ain't", "aren't", "can't", "could've", "couldn't", "didn't",
			"doesn't", "don't", "hasn't", "he'd", "he'll", "he's", "how'd", "how'll", "how's", "i'd", "i'll", "i'm", "i've", "isn't", "it's",
			"might've", "mightn't", "must've", "mustn't", "shan't", "she'd", "she'll", "she's", "should've", "shouldn't", "that'll", "that's",
			"there's", "they'd", "they'll", "they're", "they've", "wasn't", "we'd", "we'll", "we're", "weren't", "what'd", "what's", "when'd",
			"when'll", "when's", "where'd", "where'll", "where's", "who'd", "who'll", "who's", "why'd", "why'll", "why's", "won't", "would've",
			"wouldn't", "you'd", "you'll", "you're", "you've" }));
	// connecting keywords
	public static final HashSet<String> CONCAT_WORDS = new HashSet<String>(Arrays.asList(new String[] { "and", "&" }));

	// seperating keywords
	public static final HashSet<String> SEPERATING_WORDS = new HashSet<String>(Arrays.asList(new String[] { "or", "/" }));

	// comparing keywords
	public static final HashSet<String> COMPARING_WORDS = new HashSet<String>(Arrays.asList(new String[] { "than", "as" }));

	public static final String[] SEPERATING_CHARS = { ";", ".", "!", "?", ":" };

	public static final HashSet<String> SENTENCE_ENDING_CHARS = new HashSet<String>(Arrays.asList(new String[] { ".", "!", "?", ":" }));
	// date keywords
	public static final HashSet<String> DATE_WORDS = new HashSet<String>(Arrays.asList(new String[] { "january", "february", "march", "april", "may",
			"june", "july", "august", "september", "october", "november", "dezember", "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep",
			"oct", "nov", "dez" }));

	public static final HashSet<String> TIME_WORDS = new HashSet<String>(Arrays.asList(new String[] { "q1", "q2", "q3", "q4", "winter", "spring",
			"summer", "autumn" }));
	// cue words for software names
	public static final HashSet<String> SOFTWARE_NAME_START_WORDS = new HashSet<String>(Arrays.asList(new String[] { "in" }));
	// cue words for software version (fixed indicator) -> indicator must be
	// placed right before a software version
	public static final HashSet<String> SOFTWARE_NAME_STOP_WORDS = new HashSet<String>(Arrays.asList(new String[] { "before" }));
	// cue words for software version (not fixed until indicator) -> indicator
	// must be placed behind a software version (e.g. Java 7 and earlier )
	public static final HashSet<String> SOFTWARE_VERSION_ENDS = new HashSet<String>(Arrays.asList(new String[] { "earlier", "through", "previous",
			"lower" }));
	// cue words for software version (not fixed starting version)
	public static final HashSet<String> SOFTWARE_BEGIN_IND = new HashSet<String>(Arrays.asList(new String[] { "from", "later", "after" }));
	// cue words for a software range
	public static final HashSet<String> SOFTWARE_RANGE_IND = new HashSet<String>(Arrays.asList(new String[] { "between" }));
	// string which will be inserted by connecting text snippets
	public static final String SEPERATOR = " ";

	// features a snippet may have
	public static final String[] SNIPPET_FEATURES = { "comma", "word", "possibleversion", "name", "bigletter", "nottouse", "used", "version",
			"versionext", "os", "osext", "stopword", "concatword", "comparingword", "seperator", "namestart", "versionstart", "cuebefore",
			"cueearlier", "cuebegin", "cuebetween", "logicalend", "logicalstart" };

	// logical units which may appear in a text
	public static final HashSet<String> lOGICAL_UNITS = new HashSet<String>(Arrays.asList(new String[] { "version", "versionExtention",
			"softwarename", "date", "beforeIndicator", "earlierIndicator", "number" }));

	public static final String[] VERSION_TYPES = { "fixedversion", "lastunfixedversion" };

	public static final String[][] COMBINATION_CONDITIONS = { { "version", "version" }, { "version", "version", "version" },
			{ "version", "versionExtention", "version" }, { "version", "version", "versionExtention", "version" },
			{ "version", "versionExtention", "version", "version" }, { "softwarename", "softwarename" },
			{ "softwarename", "softwarename", "softwarename" }, { "softwarename", "softwarename", "softwarename", "softwarename" },
			{ "softwarename", "softwarename", "softwarename", "softwarename", "softwarename" } };

	public static final String START_TAGS = "<?xml version='1.0' encoding='UTF-8'?>\n<nvd xmlns:patch=\"http://scap.nist.gov/schema/patch/0.1\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:vuln=\"http://scap.nist.gov/schema/vulnerability/0.4\" xmlns:cpe-lang=\"http://cpe.mitre.org/language/2.0\" xmlns:cvss=\"http://scap.nist.gov/schema/cvss-v2/0.2\" xmlns=\"http://scap.nist.gov/schema/feed/vulnerability/2.0\" xmlns:scap-core=\"http://scap.nist.gov/schema/scap-core/0.1\" nvd_xml_version=\"2.0\" pub_date=\"2013-12-22T07:21:37\" xsi:schemaLocation=\"http://scap.nist.gov/schema/patch/0.1 http://nvd.nist.gov/schema/patch_0.1.xsd http://scap.nist.gov/schema/scap-core/0.1 http://nvd.nist.gov/schema/scap-core_0.1.xsd http://scap.nist.gov/schema/feed/vulnerability/2.0 http://nvd.nist.gov/schema/nvd-cve-feed_2.0.xsd\">\n";

	public static final String END_TAG = "</nvd>";

	/**
	 * Checks if a logical Unit type may be created
	 * 
	 * @param type
	 */
	public static boolean isValidType(String type) {
		return lOGICAL_UNITS.contains(type);
	}

	public static Vector<String[]> getConditionsByType(String type) {
		Vector<String[]> resultvector = new Vector<String[]>();
		for (int i = 0; i < COMBINATION_CONDITIONS.length; i++) {
			if (COMBINATION_CONDITIONS[i][0].equalsIgnoreCase(type))
				resultvector.add(COMBINATION_CONDITIONS[i]);
		}
		return resultvector;
	}

}
