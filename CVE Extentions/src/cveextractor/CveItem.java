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

/**
 * >> On object of this class represents a CVE Entry <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class CveItem {
	public CveItem(String xmlInput) {
		xmlCode = xmlInput;
		try {

			InputSource source = new InputSource(new StringReader(xmlCode));
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			xmlDocument = db.parse(source);
			XPathFactory xpathFactory = XPathFactory.newInstance();
			xpath = xpathFactory.newXPath();
			String summary = xpath.evaluate("//entry/summary/text()", xmlDocument);
			cveSummary = summary;

		} catch (Exception e) {
			e.printStackTrace();
		}
		initialise();

	}

	public final String xmlCode; // plain unmodified content of a CVE file

	protected Document xmlDocument; // XPath Document of CVE entry

	protected XPath xpath; // XPath object

	protected Vector<Snippet> tokenList;

	protected String cveSummary;

	/**
	 * initialization of a CVE item
	 */
	protected void initialise() {
		Vector<Snippet> description = getTokens();
		tokenList = description;
		Iterator<Snippet> tokenIterator = tokenList.iterator();
		while (tokenIterator.hasNext())
			tokenIterator.next().combine();
		rebuildTokenVector();
		searchSnippetcontext();
	}

	/**
	 * Refinement of a snippet entity
	 */
	private void searchSnippetcontext() {
		Iterator<Snippet> tokenIterator = tokenList.iterator();
		Snippet curSnip;
		while (tokenIterator.hasNext()) {
			curSnip = tokenIterator.next();
			try {
				if (curSnip.hasLogicalType()) {
					if (curSnip.hasPrev()) {
						if (curSnip.prev.condition("!cuebefore"))
							curSnip.setLogicalUnitComment("fixed");
						if (curSnip.prev.condition("!cuebegin"))
							curSnip.setLogicalUnitComment("first detected vulnerability");
						if (curSnip.prev.condition("!cueearlier"))
							curSnip.setLogicalUnitComment("last detected vulnerability");
						if (curSnip.prev.condition("!cuebetween")) {
							curSnip.setLogicalUnitComment("first detected vulnerability");
							Snippet scanSnip = curSnip;
							int distance = 0;
							while (scanSnip.hasNext() && !scanSnip.islogicalEnd() && distance < Config.SEARCH_DISTANCE) {
								scanSnip = scanSnip.next;
								distance += scanSnip.value();
								if (scanSnip.isLogicalType("version")) {
									scanSnip.setLogicalUnitComment("last detected vulnerability");
								}
							}
						}
						if (curSnip.prev.condition("!comparingword") && curSnip.prev.hasPrev()) {
							if (curSnip.prev.prev.condition("!cueearlier"))
								curSnip.setLogicalUnitComment("last detected vulnerability");
							if (curSnip.prev.prev.condition("!cuebegin"))
								curSnip.setLogicalUnitComment("first detected vulnerability");
						}

					}
					if (curSnip.hasNext() && curSnip.next.hasNext()) {
						if (curSnip.next.condition("!concatword") && curSnip.next.next.condition("!cueearlier"))
							curSnip.setLogicalUnitComment("last detected vulnerability");
					}

				}
			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}
	}

	/**
	 * XPath interface
	 * 
	 * @param command
	 *            XPath evaluation command
	 * @return XPath result string
	 */
	protected String xpathRequest(String command) {
		try {
			return xpath.evaluate(command, xmlDocument);
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return "";
	}

	/**
	 * @return XPath instance
	 */
	public XPath xPath() {
		return xpath;
	}

	/**
	 * @return XPath Document
	 */
	public Document XmlDocument() {
		return xmlDocument;
	}

	// protected String xpathFromString(String source, String command) {
	// try {
	// InputSource inputSource = new InputSource(new StringReader(source));
	// DocumentBuilderFactory docbuildfac = DocumentBuilderFactory
	// .newInstance();
	// DocumentBuilder docbuild;
	// docbuild = docbuildfac.newDocumentBuilder();
	// Document XmlDoc = docbuild.parse(inputSource);
	// XPathFactory xpathFactory = XPathFactory.newInstance();
	// XPath xpa = xpathFactory.newXPath();
	// return xpa.evaluate(command, XmlDoc);
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	// return "";
	// }

	/**
	 * @return CVE-ID string
	 */
	public String getCVEID() {
		return tagSubstr("vuln:cve-id").firstElement()[1].replaceAll("\\<.*?\\>", "");
	}

	/**
	 * @return token list of CVE summary
	 */
	public Vector<Snippet> getTokens() {
		StringTokenizer st = new StringTokenizer(cveSummary);
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
			curSnip.initialize();
			tokens.add(curSnip);
		}
		return tokens;
	}

	//
	// /**
	// * Returns the number of results fitting to the input regex.
	// *
	// * @param query
	// * regex for search process
	// * @return number of results aber search process
	// */
	// int searchfor(String query) {
	// // htmltext.matches(query);
	// int zaehler = 0;
	// Matcher matcher = Pattern.compile(query).matcher(XmlCode);
	// while (matcher.find())
	// zaehler++;
	// return zaehler;
	// }

	// /**
	// * Returns a result of a search process fitting the regex query.
	// *
	// * @param query
	// * regex for search process
	// * @param type
	// * searchtype (case sensitiv etc.)
	// * @return ArrayList with results
	// */
	// public ArrayList<String> searchForResult(String query, int type) {
	// // Sucht nach einem query und gibt das Ergebnis in einem HashSet zurück
	// Matcher ma;
	// ArrayList<String> result = new ArrayList<String>();
	// switch (type) {
	// case 6:
	// ma = Pattern.compile(query).matcher(cveSummary.toLowerCase());
	// break;
	// case 3:
	// ma = Pattern.compile(query).matcher(XmlCode.toLowerCase());
	// break;
	// default:
	// ma = Pattern.compile(query).matcher(XmlCode);
	// break;
	// }
	//
	// while(ma.find()) {
	// result.add(ma.group());
	// }
	// return result;
	// }

	// /**
	// * Returns a result of a search process fitting the regex query incl.
	// * matching positions. (currently not in use)
	// *
	// * @param query
	// * regex for search process
	// * @param type
	// * searchtype (case sensitiv etc.)
	// * @return ArrayList with results (result type = Snippet)
	// */
	// public Vector<Snippet> searchForResultPosistion(String query, int type) {
	// Matcher ma;
	// Vector<Snippet> result = new Vector<Snippet>();
	// switch (type) {
	// case 3:
	// ma = Pattern.compile(query).matcher(XmlCode.toLowerCase());
	// break;
	// default:
	// ma = Pattern.compile(query).matcher(XmlCode);
	// break;
	// }
	// while (ma.find()) { // saving matching positions in Snippets
	// // Snippet wordSnippet = new Snippet(ma.group(), ma.start());
	// // result.add(wordSnippet);
	// }
	// return result;
	// }

	// /**
	// * TODO Checks weather a String contains numbers and dots => high
	// likelihood
	// * for a software version (currently not in use)
	// *
	// * @param checkword
	// * Sting which should be checked
	// * @return Returns weather a Sting is a "numerical word"
	// */
	// public boolean isNumericalWord(String checkword) {
	// if (checkword.matches("[\\p{Punct}\\w]*[\\d.]+[\\p{Punct}\\w]*")) {
	// return true;
	// }
	// return false;
	// }

	/**
	 * Searches a Software before a Snippet
	 * 
	 * @param versionSnippet
	 *            version entity snippet
	 * @return corresponding name snippet
	 */
	public Snippet searchSoftwareNameBefore(Snippet versionSnippet) {
		Snippet curSnip = versionSnippet;
		Snippet Softwarename = null;
		int distance = 0;
		while (distance < Config.SEARCH_DISTANCE && curSnip.hasPrev()) {
			curSnip = curSnip.prev;
			if (curSnip.logicalType() != null && curSnip.logicalType().equals("softwarename")) {
				Softwarename = curSnip;
				break;
			} else {
				distance += curSnip.getTokenValue();
				if (curSnip.logicalType() != null && curSnip.logicalType().equals("version"))
					distance = 0;
			}
		}
		if (Softwarename == null)
			Softwarename = new Snippet("");
		return Softwarename;
	}

	// /**
	// * Searches for software versions, which are marked as Softwareversion
	// "and earlier".
	// * @return Search results
	// */
	// public String[] getEarlier(){
	// String[] result;
	// ArrayList<String> searchresult = searchForResult("[\\d\\.]+ and earlier",
	// 3);
	// ArrayList<String> searchresultTwo =
	// searchForResult("[\\d\\.]+ and before", 3);
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
	// /**
	// * Searches for software versions, which are marked as Softwareversion
	// * "before".
	// *
	// * @return Search results
	// */
	// public String[] getBefore() {
	// String[] result;
	// String[] keywords = Konfig.versionKeywords;
	// String keywordString = "(";
	// for (int i = 0; i < keywords.length - 1; i++) {
	// keywordString += keywords[i] + "|";
	// }
	// keywordString += keywords[keywords.length - 1] + ")";
	// ArrayList<String> searchresult = searchForResult("(before( )?("
	// + keywordString + "?( )?[.-:_+\\w]*[\\d.]+[.-:_+\\w]*"
	// + keywordString + "?)+)+", 6); // alternative: before(
	// // \\w\\w\\w+)? [\\d\\.]+\\w?
	// result = new String[searchresult.size()];
	// Iterator<String> it = searchresult.iterator();
	// int i = 0;
	// while (it.hasNext()) {
	// result[i] = it.next();
	// i++;
	// }
	// return result;
	// }
	//
	// /**
	// * Simple search method to check if a string is part of the CVE item. (NO
	// * Regex possible!)
	// *
	// * @param query
	// * search string
	// * @return weather the item contains the string
	// */
	// public boolean search(String query) {
	// int index = -1;
	// index = XmlCode.toLowerCase().indexOf(query.toLowerCase());
	// return index >= 0;
	// }
	//
	// /**
	// * Returns the first position of a regex matching.
	// *
	// * @param query
	// * search query
	// * @param type
	// * searchtype (case sensitiv etc.)
	// * @return first position of the matching
	// */
	// public int getFirstPositionOf(String query, int type) {
	// Matcher ma;
	// switch (type) {
	// case 3:
	// ma = Pattern.compile(query).matcher(XmlCode.toLowerCase());
	// break;
	// default:
	// ma = Pattern.compile(query).matcher(XmlCode);
	// break;
	// }
	// if (ma.find()) {
	// return ma.start();
	// }
	// return -1;
	// }

	/**
	 * Returns the content surrounded by a xml tag with tagname type.
	 * 
	 * @param tagname
	 *            type of an xml tag
	 * @return result of content surrounded by tags of tagname type
	 */

	public Vector<String[]> tagSubstr(String tagname) {
		// german: Liefert den Inhalt zwischen einem öffnenden und einem
		// schließenden Tag des Typs tagname
		Vector<String[]> vec = new Vector<String[]>();
		String[] partresult = null;
		String innerNoTagText;
		Matcher ma, mo;
		ma = Pattern.compile("<" + tagname + ">").matcher(xmlCode.toLowerCase());
		mo = Pattern.compile("</" + tagname + ">").matcher(xmlCode.toLowerCase());
		while (ma.find()) {
			if (mo.find(ma.end())) {
				partresult = new String[2];
				partresult[0] = tagname;
				innerNoTagText = StringEscapeUtils.unescapeXml(xmlCode.substring(ma.start(), mo.end())); // .replaceAll("\\<.*?\\>",
																											// "")
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
		if (curSnip.isLogicalType(logicalUnitType))
			returnVec.add(curSnip);
		while (curSnip.hasNext()) {
			curSnip = curSnip.next;
			if (curSnip.isLogicalType(logicalUnitType)) {
				returnVec.add(curSnip);
			}
		}

		return returnVec;
	}

	// /**
	// * Merges all version extraction procedures.
	// *
	// * @return result of version extractions
	// */
	// public String[] getFixedVersion() {
	// String[] before = getBefore();
	// // String[] earlier = getEarlier(); // not suitable for current
	// // requirements
	// for (int i = 0; i < before.length; i++) {
	// before[i] = releaseNr(before[i]);
	// }
	// return before;
	// // return ArrayUtils.addAll(before, earlier); // not suitable for
	// // current requirements
	// }

	// /**
	// * Deletes a "before" in a matching string resulted by a regex.
	// *
	// * @param workstring
	// * String with "before"
	// * @return Trimed string without before
	// */
	// public String releaseNr(String workstring) {
	// return workstring = workstring.replace("before", "").trim();
	// }

	// /**
	// * Merges all version allocation procedures.
	// *
	// * @return result of version allocations
	// */
	// public String[] getSoftware() {
	// String[] Software;
	// String[] Versions = getFixedVersion();
	// Software = new String[Versions.length];
	// for (int i = 0; i < Versions.length; i++) {
	// Software[i] = allocateSoftware(Versions[i]);
	// }
	// return Software;
	// }

	// /**
	// * Allocates a CPE String to a found software version
	// *
	// * @param version
	// * software version
	// * @return CPE string with high likelihood of matching with the software
	// * version.
	// */
	// public String allocateSoftware(String version) {
	//
	// if (tagSubstr("vuln:vulnerable-software-list").isEmpty())
	// return "CVE Vulnerability broken!";
	// String software = tagSubstr("vuln:vulnerable-software-list")
	// .firstElement()[1];
	// System.out.println("Version: " + version);
	// Matcher ma;
	// ma = Pattern.compile("[ \\p{Alpha}]").matcher(
	// version.toLowerCase().trim());
	// String versionnew = version;
	// while (ma.find()) {
	// versionnew = version.substring(0, ma.start());
	// }
	// version = versionnew;
	// // System.out.println("Anzahl an versch. Software: "+softwareCounter());
	// if (softwareCounter() == 1) { // searchfor("cpe-lang:fact-ref")
	// // System.out.println("Indexof "+XmlCode.indexOf("cpe-lang:fact-ref"));
	// int startSubStr = XmlCode.indexOf("\"",
	// XmlCode.indexOf("cpe-lang:fact-ref")) + 1;
	// // System.out.println("Start "+startSubStr);
	// int endSubStr = XmlCode.indexOf("\"", startSubStr);
	// // System.out.println("Ende "+endSubStr);
	// String partRes = XmlCode.substring(startSubStr, endSubStr);
	// // System.out.println("partRes="+partRes);
	// return partRes.substring(0, partRes.lastIndexOf(":"));
	// }
	// String search1 = version;
	// while (true) {
	// try {
	// int number = Integer.parseInt(search1.substring(search1
	// .lastIndexOf(".") + 1));
	// int checkbig = 0;
	// while (number >= 0 && checkbig < 20) {
	// String search2 = search1.substring(0,
	// search1.lastIndexOf(".") + 1)
	// + number;
	// if (software.contains(search2)) {
	// int position = software.indexOf(search2);
	// String partresult = software.substring(0, position);
	// return partresult
	// .substring(partresult.lastIndexOf(">") + 1);
	// }
	// number--;
	// checkbig++;
	// }
	//
	// } catch (Exception e) {
	//
	// }
	// if (search1.lastIndexOf(".") == -1)
	// break;
	// search1 = search1.substring(0, search1.lastIndexOf("."));
	// }
	// return "Software not allocatable!";
	// }

	// /**
	// * Returns the number of spercified software in this CVE item
	// *
	// * @return Returns the number of spercified software in this CVE item
	// */
	// public int softwareCounter() {
	// Matcher ma;
	// ma = Pattern.compile("<cpe-lang:fact-ref name=(\\S)+>").matcher(
	// XmlCode.toLowerCase());
	// HashSet<String> nameCollector = new HashSet<String>();
	// String matched = "";
	// String softwarename = "";
	// while (ma.find()) {
	// matched = ma.group();
	// // System.out.println(matched);
	// softwarename = matched.substring(matched.indexOf("\""),
	// matched.lastIndexOf(":"));
	// nameCollector.add(softwarename);
	// }
	// return nameCollector.size();
	// }

}
