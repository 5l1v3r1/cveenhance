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
import java.util.List;

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

	private static final File index_file = new File("data/index");

	private static IndexSearcher searcher;
	private static IndexReader reader;

	public static IndexSearcher getIndexSearcher() throws IOException {
		if (searcher == null) {
			Directory index = new SimpleFSDirectory(index_file);
			reader = DirectoryReader.open(index);
			searcher = new IndexSearcher(reader);
		}
		return searcher;
	}

	public static void main(String[] args) throws IOException, ParseException, ParserConfigurationException,
			XPathExpressionException, SAXException {
		// 0. Specify the analyzer for tokenizing text.
		// The same analyzer should be used for indexing and searching
		StandardAnalyzer analyzer = new StandardAnalyzer();

		// 1. create the index
		Directory index = new SimpleFSDirectory(index_file);

		IndexWriterConfig config = new IndexWriterConfig(Version.LUCENE_4_10_1, analyzer);

		IndexWriter w = new IndexWriter(index, config);

		DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
		builderFactory.setNamespaceAware(false);
		DocumentBuilder builder = null;

		builder = builderFactory.newDocumentBuilder();
		File f = new File("data/official-cpe-dictionary_v2.2.xml");

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

		TopScoreDocCollector collector = TopScoreDocCollector.create(hitsPerPage, true);
		IndexSearcher searcher = getIndexSearcher();
		searcher.search(q, collector);
		ScoreDoc[] hits = collector.topDocs().scoreDocs;

		// 4. display results
		System.out.println("Found " + hits.length + " hits.");
		for (int i = 0; i < hits.length; ++i) {
			int docId = hits[i].doc;
			Document d = searcher.doc(docId);
			System.out.println((i + 1) + ". " + d.get("title") + "\t" + d.get("CPE-Name"));
		}
	}

	public static List<String> getAllCpesWithVersionPrefix(String versionPrefix, List<String> cpes) {
		List<String> result = new ArrayList<String>();
		for (String cpe : cpes) {
			if (cpe.split(":").length > 4 && cpe.split(":")[4].startsWith(versionPrefix)) {
				result.add(cpe);
			}
		}
		return result;
	}

	public static String findTitle(String cpeName) throws IOException, ParseException {
		if (cpeName.isEmpty())
			return "";
		StandardAnalyzer analyzer = new StandardAnalyzer();
		String querystr = cpeDecoding(cpeName);

		Query q = new QueryParser("CPE-Name", analyzer).parse(querystr);

		int hitsPerPage = 100;
		IndexSearcher searcher = getIndexSearcher();
		TopScoreDocCollector collector = TopScoreDocCollector.create(hitsPerPage, true);
		searcher.search(q, collector);
		ScoreDoc[] hits = collector.topDocs().scoreDocs;
		Document doc = searcher.doc(hits[0].doc);
		String title = "";
		if (hits.length > 0)
			title = doc.get("title");
		if (!AnalyseCves.extractCPEProduct(cpeName).equalsIgnoreCase(
				AnalyseCves.extractCPEProduct(cpeEncoding(doc.get("CPE-Name")))))
			title = "";
		reader.close();
		return title;
	}

	public static String cpeDecoding(String cpe) {
		if (cpe == null)
			return "";
		String[] split = cpe.split(":");
		StringBuilder sb = new StringBuilder();
		for (String s : split) {
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
		if (cpe_ == null || cpe_.isEmpty())
			return "";
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
		doc.add(new TextField("title", title, Field.Store.YES));
		w.addDocument(doc);
	}

	public static String transformTitle(String title) {
		if (title == null)
			return "";
		return title.replaceAll("\\p{Punct}", " ");
	}

	public static void close() {
		try {
			if (reader != null)
				reader.close();
		} catch (IOException e) {
			e.printStackTrace();
		}

	}
}
