package cve.matcher;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class AbbrevaitionExtractor {

	public static void main(String[] args) throws IOException, XPathExpressionException, ParserConfigurationException, SAXException {

		FileWriter fw = new FileWriter("data/abbreviations.txt");
		Set<String> set = getAbbreviations();
		for (String s : set) {
			String token = s.replaceAll("[-_.\\/]", " ");
			try {
				Document doc = Jsoup.connect("http://www.abbreviations.com/" + token.toUpperCase()).timeout(100000).get();

				Elements tableData = doc.select("td[class=\"tal dx\"]");

				if (tableData.size() > 0) {
					int maxRanking = -1;
					for (Element el : tableData) {
						int ranking = el.siblingElements().select("td[class=\"tar vam rt\"]").get(0).select("span[class=\"sf\"]").size();
						if (ranking > maxRanking && ranking == 5) {
							maxRanking = ranking;
							fw.write(token + ":  " + el.child(0).text() + "\n");
							fw.flush();
						}

					}
				}
			} catch (Exception e) {
				FileWriter fwErr = new FileWriter("data/err.txt", true);
				fwErr.write(token + "\n");
				fwErr.close();
			}
		}

		fw.close();
	}

	public static Set<String> getAbbreviations() throws ParserConfigurationException, FileNotFoundException, SAXException, IOException,
			XPathExpressionException {
		Set<String> set = new HashSet<String>();
		DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(false);
		DocumentBuilder builder = null;
		builder = builderFactory.newDocumentBuilder();
		File f = new File("data/official-cpe-dictionary_v2.3.xml");
		org.w3c.dom.Document document = builder.parse(new FileInputStream(f));
		XPath xPath = XPathFactory.newInstance().newXPath();

		NodeList nodeList = (NodeList) xPath.evaluate("//cpe-item", document, XPathConstants.NODESET);

		for (int i = 0; i < nodeList.getLength(); i++) {
			Node node = nodeList.item(i);
			String cpe23 = "";
			for (int j = 0; j < node.getChildNodes().getLength(); j++) {
				Node fst = node.getChildNodes().item(j);
				if (fst.getNodeName().equals("cpe-23:cpe23-item")) {
					cpe23 = fst.getAttributes().getNamedItem("name").getNodeValue();
				}
			}
			if (cpe23.length() > 0 && cpe23.split(":")[2].equals("a"))
				set.add(cpe23.split(":")[4]);
		}

		return set;
	}

}
