package de.lg.versionextractor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import de.lg.searcher.WordAnnotations;

public class VersionExtractor {
	public static void main(String[] args) throws ParserConfigurationException,
			FileNotFoundException, SAXException, IOException,
			XPathExpressionException {
		DocumentBuilderFactory builderFactory = DocumentBuilderFactory
				.newInstance();
		builderFactory.setNamespaceAware(false);
		DocumentBuilder builder = null;

		FileWriter fw = new FileWriter("struts.csv");

		builder = builderFactory.newDocumentBuilder();
		File dir = new File("data/");
		for (File f : dir.listFiles()) {
			Document document = builder.parse(new FileInputStream(f));
			XPath xPath = XPathFactory.newInstance().newXPath();

			NodeList nodeList = (NodeList) xPath.evaluate("//entry", document,
					XPathConstants.NODESET);

			for (int i = 0; i < nodeList.getLength(); i++) {
				Node entry = nodeList.item(i);

				Node cveid = (Node) xPath.evaluate("cve-id/text()", entry,
						XPathConstants.NODE);
				Node summary = (Node) xPath.evaluate("summary/text()", entry,
						XPathConstants.NODE);
				NodeList vulnSoftware = (NodeList) xPath.evaluate(
						"vulnerable-software-list/product/text()", entry,
						XPathConstants.NODESET);
				if (vulnSoftware.getLength() > 0)
					for (int j = 0; j < vulnSoftware.getLength(); j++) {
						Node productNode = vulnSoftware.item(j);
						String product = productNode.getTextContent();

						if (product.contains("struts")) {
							fw.write(cveid + ";" + product + "\n");
							fw.flush();
						}

					}
				else {
					List<String> searchTerms = new ArrayList<String>();
					searchTerms.add("Struts");
					findVersionsByNames(searchTerms, cveid.getTextContent(),
							summary.getTextContent(), fw);
				}

			}
		}
		fw.close();
	}

	private static void findVersionsByNames(List<String> searchTerms,
			String cveid, String summary, FileWriter fw) throws IOException {
		StringTokenizer st = new StringTokenizer(summary);
		WordAnnotations firstWord = null;
		WordAnnotations currWord = null;
		boolean firstIter = true;
		while (st.hasMoreTokens()) {
			String token = st.nextToken();
			String firstChar = token.substring(0, 1);

			WordAnnotations wa = new WordAnnotations(token);
			if (firstChar.matches("[0-9]")) {
				wa.setPossibleVersion(true);
			} else if (firstChar.matches("[A-Z]")) {
				wa.setNotToUse(token
						.matches("(January|February|March|April|May|June|July|August|September|October|November|Dezember|Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dez)(,)?"));
				wa.setBigLetter(true);
			} else {
				wa.setBigLetter(false);
			}

			if (token.endsWith(",")) {
				wa.setComma(true);
			}

			if (firstIter) {
				firstIter = false;
				firstWord = wa;
				currWord = firstWord;
			} else {
				wa.prev = currWord;
				currWord.next = wa;
				currWord = wa;
			}
		}
		currWord = firstWord;
		String lastProduct = "";
		int lastUsed = 0;
		while (currWord != null) {
			if (!currWord.isUsed() && !currWord.isNotToUse()) {
				if (testProduct(currWord.getWord(), searchTerms)) {
					lastProduct = (currWord.searchForProductDetails(
							searchTerms));
				} else if (currWord.isBigLetter()) {
					lastProduct = currWord.searchBigLetterSuccessors();
				}

			}

			if (!currWord.isUsed() && currWord.prev != null
					&& !currWord.prev.isNotToUse()) {
				if (currWord.isPossibleVersion()) {
					String lastVersion = currWord.searchForVersionDetails();

					if (lastProduct.length() > 0 && lastUsed < 6) {
						fw.write(cveid + ";" + lastProduct + " " + lastVersion
								+ "\n");
						fw.flush();
					}
				}
			}
			if (currWord.isUsed())
				lastUsed = 0;

			lastUsed++;
			currWord = currWord.next;
		}

	}

	public static boolean testProduct(String word, List<String> searchTerms) {
		for (String searchTerm : searchTerms) {
			String[] subTerms = searchTerm.split(" ");
			if (word.equalsIgnoreCase(subTerms[0])) {
				return true;
			}
		}
		return false;

	}
}
