package tud.cpe.preparation;

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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.ScoreDoc;
import org.apache.lucene.search.TopScoreDocCollector;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.SimpleFSDirectory;
import org.apache.lucene.util.Version;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import tud.cve.extractor.AnalyseCves;

/**
 * >> This class is used to handle cpe strings <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class LuceneIndexCreator {

	public static void test(String[] args) throws IOException, ParseException, ParserConfigurationException,
			XPathExpressionException, SAXException {
		// 0. Specify the analyzer for tokenizing text.
		// The same analyzer should be used for indexing and searching
		StandardAnalyzer analyzer = new StandardAnalyzer();

		// 1. create the index
		Directory index = new SimpleFSDirectory(new File("data/index"));

		IndexWriterConfig config = new IndexWriterConfig(Version.LUCENE_4_10_1, analyzer);

		IndexWriter w = new IndexWriter(index, config);

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
			String cpename = node.getAttributes().getNamedItem("name").getNodeValue();
			String title = "";
			for (int j = 0; j < node.getChildNodes().getLength(); j++) {
				Node fst = node.getChildNodes().item(j);
				if (fst.getNodeName().equals("title")
						&& fst.getAttributes().getNamedItem("xml:lang").getNodeValue().equals("en-US")) {
					title = transformTitle(fst.getTextContent());
				}
			}
			addDoc(w, cpename, title);
		}
		w.close();

		// 2. query
		String querystr = args.length > 0 ? args[0] : "cpe a oracle jre";

		// the "title" arg specifies the default field to use
		// when no field is explicitly specified in the query.
		Query q = new QueryParser("CPE-Name", analyzer).parse(querystr);

		// 3. search
		int hitsPerPage = 100;
		IndexReader reader = DirectoryReader.open(index);
		IndexSearcher searcher = new IndexSearcher(reader);
		TopScoreDocCollector collector = TopScoreDocCollector.create(hitsPerPage, true);
		searcher.search(q, collector);
		ScoreDoc[] hits = collector.topDocs().scoreDocs;

		// 4. display results
		System.out.println("Found " + hits.length + " hits.");
		for (int i = 0; i < hits.length; ++i) {
			int docId = hits[i].doc;
			Document d = searcher.doc(docId);
			System.out.println((i + 1) + ". " + d.get("title") + "\t" + d.get("CPE-Name"));
		}

		// reader can only be closed when there
		// is no need to access the documents any more.
		reader.close();
	}

	public static void main(String[] args) throws IOException, ParseException {
		String[] cpes = { "cpe:/a:ibm:java:7.0.0.0", "cpe:/a:ibm:java:7.0.1.0", "cpe:/a:ibm:java:7.0.2.0",
				"cpe:/a:ibm:java:7.0.3.0", "cpe:/a:ibm:java:7.0.4.0", "cpe:/a:ibm:java:7.0.4.1",
				"cpe:/a:ibm:java:7.0.4.2", "cpe:/a:ibm:java:5.0.14.0", "cpe:/a:ibm:java:5.0.15.0",
				"cpe:/a:ibm:java:5.0.11.1", "cpe:/a:ibm:java:5.0.0.0", "cpe:/a:ibm:java:5.0.11.2",
				"cpe:/a:ibm:java:5.0.12.0", "cpe:/a:ibm:java:5.0.12.1", "cpe:/a:ibm:java:5.0.12.2",
				"cpe:/a:ibm:java:5.0.12.3", "cpe:/a:ibm:java:5.0.12.4", "cpe:/a:ibm:java:5.0.12.5",
				"cpe:/a:ibm:java:5.0.13.0", "cpe:/a:ibm:java:5.0.16.2", "cpe:/a:oracle:jre:5.0.16.1",
				"cpe:/a:oracle:jre:5.0.16.0", "cpe:/a:oracle:jre:5.0.11.0", "cpe:/a:ibm:java:6.0.1.0",
				"cpe:/a:ibm:java:6.0.11.0", "cpe:/a:ibm:java:6.0.10.1", "cpe:/a:ibm:java:6.0.0.0",
				"cpe:/a:ibm:java:6.0.12.0", "cpe:/a:ibm:java:6.0.2.0", "cpe:/a:ibm:java:6.0.3.0",
				"cpe:/a:ibm:java:6.0.4.0", "cpe:/a:ibm:java:6.0.5.0", "cpe:/a:ibm:java:6.0.7.0",
				"cpe:/a:ibm:java:6.0.6.0", "cpe:/a:ibm:java:6.0.8.1", "cpe:/a:ibm:java:6.0.8.0",
				"cpe:/a:sun:jre:6.0.9.1", "cpe:/a:sun:jre:6.0.9.0", "cpe:/a:ibm:java:6.0.10.0",
				"cpe:/a:ibm:java:6.0.9.2", "cpe:/a:ibm:java:6.0.13.0", "cpe:/a:ibm:java:6.0.13.1",
				"cpe:/a:ibm:java:6.0.13.2" };
		Map<String, List<String>> titles = new HashMap<String, List<String>>();
		Set<String> set = new HashSet<String>();
		for (int i = 0; i < cpes.length; i++) {
			String res = transformTitle(searchForTitle(cpes[i]));
			if (res.length() > 0) {
				String[] split = cpes[i].split(":");
				String key = split[2] + ":" + split[3];
				List<String> list = new ArrayList<String>();
				if (titles.containsKey(key)) {
					list = titles.get(key);
				}
				list.add(res.substring(0, res.indexOf(transformTitle(split[4]))));
				titles.put(key, list);
			}
		}
		for (Entry<String, List<String>> entry : titles.entrySet()) {
			String longestPrefix = entry.getValue().get(0);
			for (int i = 1; i < entry.getValue().size(); i++) {
				String next = entry.getValue().get(i);
				int minLen = Math.min(longestPrefix.length(), next.length());
				for (int j = 0; j < minLen; j++) {
					if (longestPrefix.charAt(j) != next.charAt(j)) {
						longestPrefix = longestPrefix.substring(0, j).trim();
						break;
					}
				}
			}
			set.add(longestPrefix);
		}
		for (int i = 0; i < set.size(); i++)
			System.out.println(set.toArray()[i]);
	}

	public static List<String> getAllCpesWithVersionPrefix(String versionPrefix, List<String> cpes) {
		List<String> result = new ArrayList<String>();
		for (String cpe : cpes) {
			if (cpe.split(":")[4].startsWith(versionPrefix)) {
				result.add(cpe);
			}
		}
		return result;
	}

	public static String searchForTitle(String cpeName) throws IOException, ParseException {
		StandardAnalyzer analyzer = new StandardAnalyzer();
		Directory index = new SimpleFSDirectory(new File("data/index"));
		String querystr = cpeDecoding(cpeName);

		Query q = new QueryParser("CPE-Name", analyzer).parse(querystr);

		int hitsPerPage = 100;
		IndexReader reader = DirectoryReader.open(index);
		IndexSearcher searcher = new IndexSearcher(reader);
		TopScoreDocCollector collector = TopScoreDocCollector.create(hitsPerPage, true);
		searcher.search(q, collector);
		ScoreDoc[] hits = collector.topDocs().scoreDocs;
		if (hits.length > 0)
			return searcher.doc(hits[0].doc).get("title");
		reader.close();

		return "";
	}

	public static String findTitle(String cpeName) throws IOException, ParseException {
		StandardAnalyzer analyzer = new StandardAnalyzer();
		Directory index = new SimpleFSDirectory(new File("data/index"));
		String querystr = cpeDecoding(cpeName);

		Query q = new QueryParser("CPE-Name", analyzer).parse(querystr);

		int hitsPerPage = 100;
		IndexReader reader = DirectoryReader.open(index);
		IndexSearcher searcher = new IndexSearcher(reader);
		TopScoreDocCollector collector = TopScoreDocCollector.create(hitsPerPage, true);
		searcher.search(q, collector);
		ScoreDoc[] hits = collector.topDocs().scoreDocs;
		String title = "";
		if (hits.length > 0)
			title = searcher.doc(hits[0].doc).get("title");
		reader.close();
		if (!AnalyseCves.extractCPEProduct(cpeName).equalsIgnoreCase(
				AnalyseCves.extractCPEProduct(searcher.doc(hits[0].doc).get("CPE-Name"))))
			title = "";

		return title;
	}

	public static String searchForCpeName(String title) throws IOException, ParseException {
		StandardAnalyzer analyzer = new StandardAnalyzer();
		Directory index = new SimpleFSDirectory(new File("data/index"));
		String querystr = transformTitle(title);

		Query q = new QueryParser("title", analyzer).parse(querystr);

		int hitsPerPage = 100;
		IndexReader reader = DirectoryReader.open(index);
		IndexSearcher searcher = new IndexSearcher(reader);
		TopScoreDocCollector collector = TopScoreDocCollector.create(hitsPerPage, true);
		searcher.search(q, collector);
		ScoreDoc[] hits = collector.topDocs().scoreDocs;
		if (hits.length > 0)
			return searcher.doc(hits[0].doc).get("CPE-Name");
		reader.close();

		return "";
	}

	public static String cpeDecoding(String cpe) {
		String[] split = cpe.split(":");
		StringBuilder sb = new StringBuilder();
		for (String s : split) {
			if (s != null)
				switch (s) {
				case "cpe":
					sb.append("cpe ");
					break;
				case "/a":
					sb.append("a ");
					break;
				case "/o":
					sb.append("o ");
					break;
				case "/h":
					sb.append("h ");
					break;
				default:
					sb.append(s + " ");
					break;
				}
		}
		String result = sb.toString();
		return result.substring(0, result.length() - 1);
	}

	public static String cpeEncoding(String cpe_) {
		String[] split = cpe_.split(" ");
		StringBuilder sb = new StringBuilder();
		sb.append(split[0]);
		sb.append(":");
		sb.append("/");
		sb.append(split[1]);
		sb.append(":");
		for (int i = 2; i < split.length; i++) {
			sb.append(split[i]);
			if (i < split.length - 1) {
				sb.append(":");
			}
		}
		return sb.toString();
	}

	private static void addDoc(IndexWriter w, String cpename, String title) throws IOException {
		Document doc = new Document();
		doc.add(new TextField("CPE-Name", cpeDecoding(cpename), Field.Store.YES));

		// use a string field for isbn because we don't want it tokenized
		doc.add(new TextField("title", title, Field.Store.YES));
		// doc.add(new TextField("cpe23", cpe23, Field.Store.YES));
		w.addDocument(doc);
	}

	private static String transformTitle(String title) {
		return title.replaceAll("\\p{Punct}", " ");
		// return title.replace(".", " ").replace("_", " ").replace("-", " ").replace("(", " ");
	}
}
