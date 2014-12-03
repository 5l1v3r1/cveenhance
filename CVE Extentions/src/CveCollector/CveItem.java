package CveCollector;

/**
 * >> This class is an abstract representation of a CVE XML file.<<
 * The extraction algorithm is part of this class and information is generated inside instances of this class.
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

import java.io.StringReader;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.StringEscapeUtils;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

public class CveItem {
	public CveItem(String XmlInput) {
		XmlCode = XmlInput;
		successfulData = 0;
		unsuccessfulData = 0;
		try {
			InputSource source = new InputSource(new StringReader(XmlCode));
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document XmlDocument = db.parse(source);
			XPathFactory xpathFactory = XPathFactory.newInstance();
			xpath = xpathFactory.newXPath();
			String summary = xpath.evaluate("//entry/summary/text()", XmlDocument);

			// System.out.println(summary); // prints the freetext description of a CVE item
			description = summary;

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// tagSubstr("vuln:summary").firstElement()[1];
		initialise();

	}

	protected final String XmlCode; // plain content of a CVE file

	protected Document XmlDocument;

	protected XPath xpath;

	protected Vector<Snippet> tokenList; // token list extracted of the CVE file content

	protected int successfulData; // number of allocatable fixed version numbers to softwarenames

	protected int unsuccessfulData; // number of not allocatable fixed version numbers to softwarenames

	protected String description; // content part of CVE file, which describes the CVE issue (floating text)

	protected XPath xPath;

	/**
	 * initializes a CVE item instance (currently not in use)
	 */
	protected void initialise() {
		Vector<Snippet> description = getTokens(); // gets all tokens of the summary tag in the current CVE issue
		tokenList = description;
		Iterator<Snippet> tokenIterator = tokenList.iterator();
		while (tokenIterator.hasNext())
			tokenIterator.next().melt();
		rebuildTokenVector();
	}

	protected String xpathRequest(String command) {
		try {
			return xpath.evaluate(command, XmlDocument);
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return "";
	}

	protected String xpathFromString(String source, String command) {
		try {
			InputSource inputSource = new InputSource(new StringReader(source));
			DocumentBuilderFactory docbuildfac = DocumentBuilderFactory.newInstance();
			DocumentBuilder docbuild;
			docbuild = docbuildfac.newDocumentBuilder();
			Document XmlDoc = docbuild.parse(inputSource);
			XPathFactory xpathFactory = XPathFactory.newInstance();
			XPath xpa = xpathFactory.newXPath();
			return xpa.evaluate(command, XmlDoc);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return "";
	}

	/**
	 * extracts CVE ID
	 */
	public String getCVEID() {
		return tagSubstr("vuln:cve-id").firstElement()[1].replaceAll("\\<.*?\\>", "");
	}

	/**
	 * generates tokens and saves the results (currently not in use)
	 * 
	 * @return Tokenlist of XmlCode
	 */
	public Vector<Snippet> getTokens() {
		StringTokenizer st = new StringTokenizer(description);
		Vector<Snippet> tokens = new Vector<Snippet>();
		Snippet lastSnip = null;
		Snippet curSnip = null;

		while (st.hasMoreTokens()) {
			lastSnip = curSnip;
			curSnip = new Snippet(st.nextToken());
			if (lastSnip != null) {
				lastSnip.next = curSnip;
				curSnip.prev = lastSnip;
			}
			tokens.add(curSnip);
			curSnip.init();
		}

		return tokens;
	}

	//
	// /**
	// * returns the next tokens (currently not in use)
	// */
	// Snippet getNextToken(int position){
	// return tokenList.get(position++);
	// }
	//
	// /**
	// * returns the next tokens (currently not in use)
	// */
	// Snippet getNextToken(Snippet curSnip){
	// return null; //tokenList.get(curSnip.getStart()+1);
	// }
	//
	// /**
	// * returns the last tokens (currently not in use)
	// */
	// Snippet getBeforeToken(int position){
	// return tokenList.get(position--);
	// }
	//
	// /**
	// * returns the last tokens (currently not in use)
	// */
	// Snippet getBeforeToken(Snippet curSnip){
	// return null;// tokenList.get(curSnip.getStart()-1);
	// }

	/**
	 * Returns the number of results fitting to the input regex.
	 * 
	 * @param query
	 *            regex for search process
	 * @return number of results aber search process
	 */
	int searchfor(String query) {
		// htmltext.matches(query);
		int zaehler = 0;
		Matcher matcher = Pattern.compile(query).matcher(XmlCode);
		while (matcher.find())
			zaehler++;
		return zaehler;
	}

	/**
	 * Returns a result of a search process fitting the regex query.
	 * 
	 * @param query
	 *            regex for search process
	 * @param type
	 *            searchtype (case sensitiv etc.)
	 * @return ArrayList with results
	 */
	public ArrayList<String> searchForResult(String query, int type) { // Sucht nach einem query und gibt das Ergebnis in einem HashSet zurück
		Matcher ma;
		ArrayList<String> result = new ArrayList<String>();
		switch (type) {
		case 6:
			ma = Pattern.compile(query).matcher(description.toLowerCase());
			break;
		case 3:
			ma = Pattern.compile(query).matcher(XmlCode.toLowerCase());
			break;
		default:
			ma = Pattern.compile(query).matcher(XmlCode);
			break;
		}

		for (int p = 0; ma.find(); p++) {
			result.add(ma.group());
		}
		return result;
	}

	/**
	 * Returns a result of a search process fitting the regex query incl. matching positions. (currently not in use)
	 * 
	 * @param query
	 *            regex for search process
	 * @param type
	 *            searchtype (case sensitiv etc.)
	 * @return ArrayList with results (result type = Snippet)
	 */
	public Vector<Snippet> searchForResultPosistion(String query, int type) {
		Matcher ma;
		Vector<Snippet> result = new Vector<Snippet>();
		switch (type) {
		case 3:
			ma = Pattern.compile(query).matcher(XmlCode.toLowerCase());
			break;
		default:
			ma = Pattern.compile(query).matcher(XmlCode);
			break;
		}
		while (ma.find()) { // saving matching positions in Snippets
			// Snippet wordSnippet = new Snippet(ma.group(), ma.start());
			// result.add(wordSnippet);
		}
		return result;
	}

	/**
	 * TODO Checks weather a String contains numbers and dots => high likelihood for a software version (currently not in use)
	 * 
	 * @param checkword
	 *            Sting which should be checked
	 * @return Returns weather a Sting is a "numerical word"
	 */
	public boolean isNumericalWord(String checkword) {
		if (checkword.matches("[\\p{Punct}\\w]*[\\d.]+[\\p{Punct}\\w]*")) {
			return true;
		}
		return false;
	}

	// /**
	// * TODO
	// * Searches a Software before a Snippet (currently not in use / not implemented)
	// * @param versionSnippet
	// * @return
	// */
	// public String searchSoftwareNameBefore(Snippet versionSnippet){
	// Matcher ma;
	// String Softwarename="";
	// TODO
	// return Softwarename;
	// }

	// /**
	// * Searches for software versions, which are marked as Softwareversion "and earlier".
	// * @return Search results
	// */
	// public String[] getEarlier(){
	// String[] result;
	// ArrayList<String> searchresult = searchForResult("[\\d\\.]+ and earlier", 3);
	// ArrayList<String> searchresultTwo = searchForResult("[\\d\\.]+ and before", 3);
	// result=new String[searchresult.size()+searchresultTwo.size()];
	// Iterator<String> it=searchresult.iterator();
	// int i=0;
	// while(it.hasNext()){result[i]=it.next();i++;}
	// it=searchresultTwo.iterator();
	// i=0;
	// while(it.hasNext()){result[i]=it.next();i++;}
	// return result;
	// }
	//
	/**
	 * Searches for software versions, which are marked as Softwareversion "before".
	 * 
	 * @return Search results
	 */
	public String[] getBefore() {
		String[] result;
		String[] keywords = konfig.versionKeywords;
		String keywordString = "(";
		for (int i = 0; i < keywords.length - 1; i++) {
			keywordString += keywords[i] + "|";
		}
		keywordString += keywords[keywords.length - 1] + ")";
		ArrayList<String> searchresult = searchForResult("(before( )?(" + keywordString + "?( )?[.-:_+\\w]*[\\d.]+[.-:_+\\w]*" + keywordString
				+ "?)+)+", 6); // alternative: before( \\w\\w\\w+)? [\\d\\.]+\\w?
		result = new String[searchresult.size()];
		Iterator<String> it = searchresult.iterator();
		int i = 0;
		while (it.hasNext()) {
			result[i] = it.next();
			i++;
		}
		return result;
	}

	/**
	 * Simple search method to check if a string is part of the CVE item. (NO Regex possible!)
	 * 
	 * @param query
	 *            search string
	 * @return weather the item contains the string
	 */
	public boolean search(String query) {
		int index = -1;
		index = XmlCode.toLowerCase().indexOf(query.toLowerCase());
		return index >= 0;
	}

	/**
	 * Returns the first position of a regex matching.
	 * 
	 * @param query
	 *            search query
	 * @param type
	 *            searchtype (case sensitiv etc.)
	 * @return first position of the matching
	 */
	public int getFirstPositionOf(String query, int type) {
		Matcher ma;
		switch (type) {
		case 3:
			ma = Pattern.compile(query).matcher(XmlCode.toLowerCase());
			break;
		default:
			ma = Pattern.compile(query).matcher(XmlCode);
			break;
		}
		if (ma.find()) {
			return ma.start();
		}
		return -1;
	}

	/**
	 * Returns the content surrounded by a xml tag with tagname type.
	 * 
	 * @param tagname
	 *            type of an xml tag
	 * @return result of content surrounded by tags of tagname type
	 */

	public Vector<String[]> tagSubstr(String tagname) { // german: Liefert den Inhalt zwischen einem öffnenden und einem schließenden Tag des Typs
														// tagname
		Vector<String[]> vec = new Vector<String[]>();
		String[] partresult = null;
		String innerNoTagText;
		Matcher ma, mo;
		ma = Pattern.compile("<" + tagname + ">").matcher(XmlCode.toLowerCase());
		mo = Pattern.compile("</" + tagname + ">").matcher(XmlCode.toLowerCase());
		while (ma.find()) {
			if (mo.find(ma.end())) {
				partresult = new String[2];
				partresult[0] = tagname;
				innerNoTagText = StringEscapeUtils.unescapeXml(XmlCode.substring(ma.start(), mo.end())); // .replaceAll("\\<.*?\\>", "")
				innerNoTagText = innerNoTagText.replaceAll("[\\t\\n\\f\\r]", "");
				partresult[1] = innerNoTagText;
				vec.add(partresult);
			} else {
				System.out.println("FEHLER: Der Tag </" + tagname + "> konnte nicht gefunden werden!");
			}
		}
		return vec;
	}

	public void rebuildTokenVector() {
		Vector<Snippet> newtokenList = new Vector<Snippet>();
		Snippet curSnip = tokenList.firstElement();
		newtokenList.add(curSnip);
		while (curSnip.hasNext()) {
			curSnip = curSnip.next;
			newtokenList.add(curSnip);
		}
	}

	Vector<Snippet> getSnippetsWithLogicalUnits(String logicalUnitType) {
		Vector<Snippet> returnVec = new Vector<Snippet>();
		Snippet curSnip = tokenList.firstElement();
		if (curSnip.hasLogicalType(logicalUnitType))
			returnVec.add(curSnip);
		while (curSnip.hasNext()) {
			curSnip = curSnip.next;
			if (curSnip.hasLogicalType(logicalUnitType))
				returnVec.add(curSnip);
		}
		return returnVec;
	}

	/*
	 * public Vector<String[]> tagSubstr(String tagname){ // german: Liefert den Inhalt zwischen einem öffnenden und einem schließenden Tag des Typs
	 * tagname Vector<String[]> vec= new Vector<String[]>(); String[] partresult = null; String innerNoTagText; Matcher ma, mo; ma =
	 * Pattern.compile("<"+tagname+">").matcher(XmlCode.toLowerCase()); mo = Pattern.compile("</"+tagname+">").matcher(XmlCode.toLowerCase()); while
	 * (ma.find()){ if(mo.find(ma.end())){ partresult= new String[2]; partresult[0]=tagname;
	 * innerNoTagText=StringEscapeUtils.unescapeXml(XmlCode.substring(ma.start(), mo.end())); //.replaceAll("\\<.*?\\>", "")
	 * innerNoTagText=innerNoTagText.replaceAll("[\\t\\n\\f\\r]", ""); partresult[1]=innerNoTagText; vec.add(partresult); } else{
	 * System.out.println("FEHLER: Der Tag </"+tagname+"> konnte nicht gefunden werden!"); } } return vec; }
	 */
	/**
	 * Merges all version extraction procedures.
	 * 
	 * @return result of version extractions
	 */
	public String[] getFixedVersion() {
		String[] before = getBefore();
		// String[] earlier = getEarlier(); // not suitable for current requirements
		for (int i = 0; i < before.length; i++) {
			before[i] = releaseNr(before[i]);
		}
		return before;
		// return ArrayUtils.addAll(before, earlier); // not suitable for current requirements
	}

	/**
	 * Deletes a "before" in a matching string resulted by a regex.
	 * 
	 * @param workstring
	 *            String with "before"
	 * @return Trimed string without before
	 */
	public String releaseNr(String workstring) {
		return workstring = workstring.replace("before", "").trim();
	}

	/**
	 * Merges all version allocation procedures.
	 * 
	 * @return result of version allocations
	 */
	public String[] getSoftware() {
		String[] Software;
		String[] Versions = getFixedVersion();
		Software = new String[Versions.length];
		for (int i = 0; i < Versions.length; i++) {
			Software[i] = allocateSoftware(Versions[i]);
		}
		return Software;
	}

	/**
	 * Allocates a CPE String to a found software version
	 * 
	 * @param version
	 *            software version
	 * @return CPE string with high likelihood of matching with the software version.
	 */
	public String allocateSoftware(String version) {

		if (tagSubstr("vuln:vulnerable-software-list").isEmpty())
			return "CVE Vulnerability broken!";
		String software = tagSubstr("vuln:vulnerable-software-list").firstElement()[1];
		System.out.println("Version: " + version);
		Matcher ma;
		ma = Pattern.compile("[ \\p{Alpha}]").matcher(version.toLowerCase().trim());
		String versionnew = version;
		String versionold = version;
		while (ma.find()) {
			versionnew = version.substring(0, ma.start());
		}
		version = versionnew;
		// System.out.println("Anzahl an versch. Software: "+softwareCounter());
		if (softwareCounter() == 1) { // searchfor("cpe-lang:fact-ref")
			// System.out.println("Indexof "+XmlCode.indexOf("cpe-lang:fact-ref"));
			int startSubStr = XmlCode.indexOf("\"", XmlCode.indexOf("cpe-lang:fact-ref")) + 1;
			// System.out.println("Start "+startSubStr);
			int endSubStr = XmlCode.indexOf("\"", startSubStr);
			// System.out.println("Ende "+endSubStr);
			String partRes = XmlCode.substring(startSubStr, endSubStr);
			// System.out.println("partRes="+partRes);
			return partRes.substring(0, partRes.lastIndexOf(":"));
		}
		String search1 = version;
		while (true) {
			try {
				int number = Integer.parseInt(search1.substring(search1.lastIndexOf(".") + 1));
				int checkbig = 0;
				while (number >= 0 && checkbig < 20) {
					String search2 = search1.substring(0, search1.lastIndexOf(".") + 1) + number;
					if (software.contains(search2)) {
						int position = software.indexOf(search2);
						String partresult = software.substring(0, position);
						successfulData++;
						return partresult.substring(partresult.lastIndexOf(">") + 1);
					}
					number--;
					checkbig++;
				}

			} catch (Exception e) {

			}
			if (search1.lastIndexOf(".") == -1)
				break; // TODO: Checken, ob es zu Fehlern bei der Auwertung kommen kann (vor allem: die Einstufung als Successful, anstatt
						// Unsuccessful)
			search1 = search1.substring(0, search1.lastIndexOf("."));
		}
		unsuccessfulData++;
		return "Software not allocatable!";
	}

	/**
	 * Returns the number of spercified software in this CVE item
	 * 
	 * @return Returns the number of spercified software in this CVE item
	 */
	public int softwareCounter() {
		Matcher ma;
		ma = Pattern.compile("<cpe-lang:fact-ref name=(\\S)+>").matcher(XmlCode.toLowerCase());
		HashSet<String> nameCollector = new HashSet<String>();
		String matched = "";
		String softwarename = "";
		while (ma.find()) {
			matched = ma.group();
			// System.out.println(matched);
			softwarename = matched.substring(matched.indexOf("\""), matched.lastIndexOf(":"));
			nameCollector.add(softwarename);
		}
		return nameCollector.size();
	}

	/**
	 * Returns number of valid data found in this file
	 * 
	 * @return number of valid data found in this file
	 */
	public int getValidData() {
		return successfulData;
	}

	/**
	 * Returns number of not valid data in this file
	 * 
	 * @return number of not valid data in this file
	 */
	public int getUnValidData() {
		return unsuccessfulData;
	}

	/**
	 * Returns information surrounded by multiple XML tags (currently not in use!)
	 * 
	 * @return -
	 */
	// public Vector<String[]> getTaggedInformation(){
	// Vector<String[]> vec= new Vector<String[]>();
	// /*
	// Beispiel: vec.addAll(tagSubstr("inst"));
	// */
	// return vec;
	// }

}
