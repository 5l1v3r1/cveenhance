package tud.cve.extractor;

/*
 * This work is licensed under the MIT License. 
 * The MIT License (MIT)

 * Copyright (c) 2015  Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), 
 * Ben Hermann (STG), Technische Universität Darmstadt

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
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
import java.util.Iterator;
import java.util.List;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.StringEscapeUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import tud.cve.data.representation.Snippet;

/**
 * >> An object of this class represents a CVE Entry <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class CveItem {
	public CveItem(String xmlInput) {
		xmlCode = xmlInput;
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
		try {

			InputSource source = new InputSource(new StringReader(xmlCode));
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			DocumentBuilder db = dbf.newDocumentBuilder();
			xmlDocument = db.parse(source);
			XPathFactory xpathFactory = XPathFactory.newInstance();
			xpath = xpathFactory.newXPath();
			String summary = xpath.evaluate("//entry/summary/text()", xmlDocument);
			if (summary.length() == 0)
				throw new Exception("The summary is empty");
			cveSummary = summary;

			Vector<Snippet> description = getTokens();
			tokenList = description;
			Iterator<Snippet> tokenIterator = tokenList.iterator();
			while (tokenIterator.hasNext())
				tokenIterator.next().combine();
			rebuildTokenVector();
			searchSnippetcontext();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Refinement of a snippet entity
	 */
	public void searchSnippetcontext() {
		Iterator<Snippet> tokenIterator = tokenList.iterator();
		Snippet curSnip;
		while (tokenIterator.hasNext()) {
			curSnip = tokenIterator.next();
			try {
				if (curSnip.hasLogicalUnit()) {
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
						if(curSnip.prev.condition("!endsafter")){
							curSnip.setLogicalUnitComment("last detected vulnerability");
							if(curSnip.prev.hasPrev()){
								if(curSnip.prev.condition("!concatword")){
									if(curSnip.prev.hasPrev()&&curSnip.prev.prev.condition("version")){
										curSnip.prev.prev.setLogicalUnitComment("first detected vulnerability");
									}
								}
								else if(curSnip.prev.condition("version")){
									curSnip.prev.setLogicalUnitComment("first detected vulnerability");
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
					
					if (curSnip.condition("version")&&curSnip.getText().endsWith(".x")){
						curSnip.setLogicalUnitComment("first detected vulnerability");
					}

				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
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
			if (curSnip.logicalUnit() != null && curSnip.logicalUnit().equals("softwarename")) {
				Softwarename = curSnip;
				break;
			} else {
				distance += curSnip.getTokenValue();
				if (curSnip.logicalUnit() != null && curSnip.logicalUnit().equals("version"))
					distance = 0;
			}
		}
		if (Softwarename == null)
			Softwarename = new Snippet("");
		return Softwarename;
	}

	/**
	 * Returns the content surrounded by a xml tag with tagname type.
	 * 
	 * @param tagname
	 *            type of an xml tag
	 * @return result of content surrounded by tags of tagname type
	 */

	public Vector<String[]> tagSubstr(String tagname) {
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
				innerNoTagText = StringEscapeUtils.unescapeXml(xmlCode.substring(ma.start(), mo.end()));
				innerNoTagText = innerNoTagText.replaceAll("[\\t\\n\\f\\r]", "");
				partresult[1] = innerNoTagText;
				vec.add(partresult);
			} else {
				System.out.println("FEHLER: Der Tag </" + tagname + "> konnte nicht gefunden werden!");
			}
		}
		return vec;
	}

	/**
	 * Rebuilds connections between Snippets after a snippet combination
	 */
	public void rebuildTokenVector() {
		Vector<Snippet> newtokenList = new Vector<Snippet>();
		Snippet curSnip = tokenList.firstElement();
		newtokenList.add(curSnip);
		while (curSnip.hasNext()) {
			curSnip = curSnip.next;
			newtokenList.add(curSnip);
		}
	}

	/**
	 * @return all Snippets with the desired logical unit (entity)
	 */
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

	/**
	 * Extracts the vulnerable software list
	 * 
	 * @return software list
	 */

	public List<String> getCpeList() {
		List<String> products = new ArrayList<String>();
		try {
			NodeList vulnSoftware = (NodeList) xPath().evaluate("//entry/vulnerable-software-list/product/text()",
					XmlDocument(), XPathConstants.NODESET);
			if (vulnSoftware.getLength() > 0) {
				for (int j = 0; j < vulnSoftware.getLength(); j++) {
					Node productNode = vulnSoftware.item(j);
					String product = productNode.getTextContent();
					products.add(product);
				}
			}
		} catch (XPathExpressionException e) {
			e.printStackTrace();
		}
		return products;
	}

}
