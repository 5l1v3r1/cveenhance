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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import cveextractor.LuceneIndexCreator;
import cveextractor.VersionComparator;

/**
 * >> This class contains the extractor main <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class AnalyseCves {

	private static Vector<String> fileDirections = new Vector<String>();

	private int[] resultCounter = new int[4];

	public static void main(String[] args) {
		AnalyseCves ana = new AnalyseCves();
		String analyseDir = "";
		if (Config.TEST_MODE)
			analyseDir = Config.CVE_SUBSET_FOLDER;
		else
			analyseDir = Config.CVE_FOLDER;
		try {
			Writer fw = new FileWriter(Config.CVE_PRINT);

			Writer bw = new BufferedWriter(fw);
			PrintWriter pw = new PrintWriter(bw);

			System.out.println("\nSelected Folder: " + System.getProperty("user.dir") + "\\" + analyseDir + "\n");
			ana.walk(analyseDir, pw);
			System.out.println("\n" + fileDirections.size() + " CVE entries analyzed in " + analyseDir + "\n");
			pw.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * This method "walks" recursive through the current directory (path) and collects all analyzable files in the file list.
	 * 
	 * @param path
	 *            path which should be analyzed; files be saved in filelist
	 * 
	 */
	public void walk(String path, PrintWriter pw) {
		File root = new File(path);
		File[] list = root.listFiles();
		BufferedWriter bw = null;
		String year = "";

		try {
			for (File f : list) {
				if (f.isDirectory()) {
					walk(f.getAbsolutePath(), pw);
					System.out.println("Dir:" + f.getAbsoluteFile());
				} else {
					String fileYear = f.getName().substring(4, 8);
					if (!year.equals(fileYear)) {
						year = fileYear;
						if (bw != null) {
							bw.write(Config.END_TAG);
							bw.close();
						}
						File folder = new File(Config.OUTPUT_FOLDER);
						if (!folder.exists())
							folder.mkdirs();
						bw = new BufferedWriter(new FileWriter(new File(Config.OUTPUT_FOLDER, "nvdcve-2.0-" + year + "-enhanced.xml")));
						bw.write(Config.START_TAGS);
					}
					String fileresult = f.getAbsoluteFile().toString();
					String parseName = fileresult.substring(fileresult.lastIndexOf("\\"));
					if (parseName.toLowerCase().contains(Config.DATA_TYPE)) {
						fileDirections.add(f.getAbsolutePath());
						StringBuilder innerText = new StringBuilder();
						try {
							FileInputStream fstream = new FileInputStream(f.getAbsolutePath());
							DataInputStream in = new DataInputStream(fstream);
							BufferedReader br = new BufferedReader(new InputStreamReader(in));
							String line;
							while ((line = br.readLine()) != null) {
								innerText.append(line);
								innerText.append("\n");
							}
							br.close();

						} catch (Exception e) {
							e.printStackTrace();
						}
						CveItem curItem = new CveItem(innerText.toString());
						resultCounter[0]++;

						this.analyse(curItem, pw, bw);
						if (Config.TEST_MODE)
							System.out.println("File:" + f.getAbsoluteFile());
						else if (resultCounter[0] % 50 == 0)
							System.out.println(resultCounter[0] + " files read");

					} else
						System.out.println("No XML File:" + f.getAbsoluteFile());
				}
			}
			if (bw != null) {
				bw.write(Config.END_TAG);
				bw.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		System.out.println("\nCVE entries: " + resultCounter[0] + "\nCVE entries with first information: " + resultCounter[1]
				+ "\nCVE entries with last information: " + resultCounter[2] + "\nCVE entries with fix information: " + resultCounter[3] + "\n");
	}

	/**
	 * This method is used to extract information of a single CVE entry.
	 * 
	 */
	private void analyse(CveItem item, PrintWriter pw, BufferedWriter bw) {
		try {
			if (Config.TEST_MODE)
				System.out.println("------- CVE-Item: " + item.getCVEID() + " -------");
			Vector<Snippet> versions = item.getSnippetsWithLogicalUnits("version");
			Vector<NameVersionRelation> relations = new Vector<NameVersionRelation>();
			Iterator<Snippet> versionIt = versions.iterator();
			Snippet curSnip;
			Snippet softwareName;
			while (versionIt.hasNext()) {
				String snippetComment = "";
				curSnip = versionIt.next();
				softwareName = item.searchSoftwareNameBefore(curSnip);
				if (!curSnip.logicalUnitComment().equals(""))
					snippetComment = "    (" + curSnip.logicalUnitComment() + ") ";
				relations.add(new NameVersionRelation(softwareName, curSnip));
				if (Config.TEST_MODE)
					System.out.println(softwareName.getText() + "     Version:" + curSnip.getText() + snippetComment);
			}

			Vector<VersionRange> results = createResult(relations, item);
			String entry = item.xmlCode;
			BufferedReader br = new BufferedReader(new StringReader(entry));
			String line;
			while ((line = br.readLine()) != null) {
				if (line.contains("</entry>")) {
					bw.write(getOutputToXMLFile(results) + "\n");
				}
				bw.write(line + "\n");
			}

			StringBuilder output = new StringBuilder();

			boolean hasFirst = false;
			boolean hasLast = false;
			boolean hasFix = false;

			for (VersionRange result : results) {
				if (result.hasFirst())
					hasFirst = true;
				if (result.hasLast())
					hasLast = true;
				if (result.hasFix())
					hasFix = true;
				if (Config.TEST_MODE)
					System.out.println("-> Result: " + result);
				else {
					if (!Config.LOGGING) {
						output = getMachineReadableOutput(item, result);
					} else {
						output = getHumanReviewOutput(item, result);
					}
					pw.println(output.toString());
				}
			}

			if (hasFirst)
				resultCounter[1]++;
			if (hasLast)
				resultCounter[2]++;
			if (hasFix)
				resultCounter[3]++;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Creates a human readable text output of extraction results
	 * 
	 * @param item
	 *            CVE entry
	 * @param result
	 *            A version range result
	 * @return human readable output string
	 */
	private StringBuilder getHumanReviewOutput(CveItem item, VersionRange result) {
		StringBuilder output = new StringBuilder();
		output.append(item.getCVEID());
		output.append("  ");
		output.append(result.toString());
		output.append("  ");
		output.append(result.cpe());
		return output;
	}

	/**
	 * Creates an XML Output
	 * 
	 * @param results
	 *            extracted version ranges
	 * @return XML output string
	 */

	private String getOutputToXMLFile(Vector<VersionRange> results) {
		StringBuilder sb = new StringBuilder();
		sb.append("\t<");
		sb.append(Config.XML_EXTENSION_TAG);
		sb.append(":");
		sb.append("ranges>\n");
		for (VersionRange vr : results) {
			sb.append(vr.getXMLRange());
		}
		sb.append("\t</");
		sb.append(Config.XML_EXTENSION_TAG);
		sb.append(":");
		sb.append("ranges>");
		return sb.toString();
	}

	/**
	 * Creates a machine readable text output of extraction results
	 * 
	 * @param item
	 *            CVE entry
	 * @param result
	 *            A version range result
	 * @return machine readable output string
	 */
	private StringBuilder getMachineReadableOutput(CveItem item, VersionRange result) {
		StringBuilder output = new StringBuilder();
		output.append(item.getCVEID());
		output.append(";");
		output.append(result.cpe());
		output.append(";");
		output.append(result.firstDetectedVersion());
		output.append(";");
		output.append(result.lastDetectedVersion());
		output.append(";");
		output.append(result.fixedVersion());
		output.append(";");
		return output.append(result.toString());
	}

	/**
	 * Creates the result of a single extraction
	 * 
	 * @param relations
	 *            all found NameVersionRelations of a CVE entry
	 * @param item
	 *            the corresponding CVE entry
	 * @return resulting version ranges
	 */
	private Vector<VersionRange> createResult(Vector<NameVersionRelation> relations, CveItem item) {

		HashSet<NameVersionRelation> interestingRelations = new HashSet<NameVersionRelation>();
		interestingRelations.addAll(relations);

		HashSet<NameVersionRelation> remainingRelations = new HashSet<NameVersionRelation>();
		HashSet<NameVersionRelation> shortestRelations = new HashSet<NameVersionRelation>();
		Vector<VersionRange> relatedRelations = new Vector<VersionRange>();

		if (interestingRelations.size() > 0) {

			relatedRelations = groupRelations(relations, interestingRelations, remainingRelations, shortestRelations);

			for (VersionRange versionRange : relatedRelations) {
				List<String> products = getProductList(item);
				String cpename = extractCPE(versionRange, products);
				if (!cpename.isEmpty()) {
					cpename = extractCPEVendor(cpename);
					versionRange.setCPE(cpename);
					// cpe:/a:apache:camel:
					List<String> remaining = fillRemainings(products, cpename);

					if (remaining.size() > 0) {
						List<String> filteredRemainings = LuceneIndexCreator.getAllCpesWithVersionPrefix(versionRange.shortest().version().getText(),
								remaining);

						if (!versionRange.hasLast()) {
							if (filteredRemainings.size() != 0)
								remaining = filteredRemainings;
							String greatest = "";
							if (versionRange.fixed()) {
								String fix = versionRange.fixedSoftware().getText();
								greatest = VersionComparator.getGreatestUnderFix(remaining, fix);
							} else
								greatest = VersionComparator.getGreatestMatch(remaining);
							if (!greatest.isEmpty())
								versionRange.setLast(greatest);
						}
					}
				}

			}
		}
		return relatedRelations;
	}

	/**
	 * extracts the vendor part of a CPEstring
	 * 
	 * @param cpename
	 *            complete CPE string
	 * @return vendor part of CPE
	 */
	private String extractCPEVendor(String cpename) {
		String[] split = cpename.split(":");
		cpename = "";
		for (int i = 0; i < 4; i++) {
			cpename += split[i] + ":";
		}
		return cpename;
	}

	private List<String> fillRemainings(List<String> products, String cpename) {
		List<String> remaining = new ArrayList<String>();
		for (String product : products) {
			if (product.startsWith(cpename))
				remaining.add(product);
		}
		return remaining;
	}

	/**
	 * Extracts the vulnerable software list
	 * 
	 * @param item
	 *            CVE item, whose software list should be extracted
	 * @return software list
	 */

	private List<String> getProductList(CveItem item) {
		List<String> products = new ArrayList<String>();
		try {
			NodeList vulnSoftware = (NodeList) item.xPath().evaluate("//entry/vulnerable-software-list/product/text()", item.XmlDocument(),
					XPathConstants.NODESET);
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

	/**
	 * Groups NameVersionRelations to VersionRanges
	 * 
	 * @param relations
	 *            all relations
	 * @return A vector of version ranges
	 */
	private Vector<VersionRange> groupRelations(Vector<NameVersionRelation> relations, HashSet<NameVersionRelation> interestingRelations,
			HashSet<NameVersionRelation> remainingRelations, HashSet<NameVersionRelation> shortestRelations) {
		Vector<VersionRange> relatedRelations = new Vector<VersionRange>();
		while (interestingRelations.size() > 0) {
			Iterator<NameVersionRelation> relationsIterator = interestingRelations.iterator();
			NameVersionRelation shortestRelation = relationsIterator.next();
			shortestRelations.add(shortestRelation);

			while (relationsIterator.hasNext()) {
				NameVersionRelation curRelation = relationsIterator.next();
				if (shortestRelation.trimmedVersion().length() > curRelation.trimmedVersion().length()) {
					shortestRelation = curRelation;
					remainingRelations.addAll(shortestRelations);
					shortestRelations.clear();
					shortestRelations.add(curRelation);
				} else if (shortestRelation.trimmedVersion().length() == curRelation.trimmedVersion().length()) {
					shortestRelations.add(curRelation);
				} else {
					remainingRelations.add(curRelation);
				}
			}

			interestingRelations.removeAll(shortestRelations);
			boolean sameSoftwareRef = isSameSoftwareRef(shortestRelations, shortestRelation);

			if (shortestRelations.size() == relations.size() && sameSoftwareRef) {
				VersionRange versionRange = new VersionRange();
				versionRange.addAll(shortestRelations);
				relatedRelations.add(versionRange);
			} else {
				for (NameVersionRelation curShortestRel : shortestRelations) {
					HashSet<NameVersionRelation> curRelRelation = new HashSet<NameVersionRelation>();
					curRelRelation.add(curShortestRel);

					allocateRemainingRelations(interestingRelations, remainingRelations, curShortestRel, curRelRelation);

					VersionRange versionRange = new VersionRange();
					versionRange.addAll(curRelRelation);
					remainingRelations.removeAll(curRelRelation);
					relatedRelations.add(versionRange);
				}

				shortestRelations.clear();
				remainingRelations.clear();
			}
		}

		return relatedRelations;
	}

	/**
	 * Checks, if a NameVersionRelation refers to the same software name
	 * 
	 * @param shortestRelations
	 *            Relation list for inserting shortest relation
	 * @param shortestRelation
	 *            relation to insert in shortest Relations
	 */
	private boolean isSameSoftwareRef(HashSet<NameVersionRelation> shortestRelations, NameVersionRelation shortestRelation) {

		boolean sameSoftwareRef = false;
		for (NameVersionRelation nameVersionRealtion : shortestRelations) {
			if (shortestRelation.refersSameSoftware(nameVersionRealtion)) {
				sameSoftwareRef = true;
			} else {
				sameSoftwareRef = false;
				break;
			}
		}
		return sameSoftwareRef;
	}

	private void allocateRemainingRelations(HashSet<NameVersionRelation> interestingRelations, HashSet<NameVersionRelation> remainingRelations,
			NameVersionRelation curShortestRel, HashSet<NameVersionRelation> curRelRelation) {
		for (NameVersionRelation curNameVerRel : remainingRelations) {
			if (curNameVerRel.refersSameSoftware(curShortestRel)
					&& (curShortestRel.versionIsMoreGeneral(curNameVerRel) || curShortestRel.hasSameSuperversion(curNameVerRel))) {
				curRelRelation.add(curNameVerRel);
				interestingRelations.remove(curNameVerRel);
			}
		}
	}

	/**
	 * Returns the most alike cpe string
	 * 
	 * @param versionRange
	 * @param products
	 * @return most alike cpe string
	 */
	private String extractCPE(VersionRange versionRange, List<String> products) {
		int levenshteinDistance = Integer.MAX_VALUE;
		String cpe = "";
		String softwareName = versionRange.shortest().name().getText() + " " + versionRange.shortest().version().getText();
		int currentdistance;
		for (String product : products) {
			currentdistance = getLevenshteinDistance(product, softwareName);
			if (currentdistance < levenshteinDistance) {
				cpe = product;
				levenshteinDistance = currentdistance;
			}
		}
		return cpe;
	}

	/**
	 * Calculates the levensthein distance
	 * 
	 * @param first
	 *            first String
	 * @param second
	 *            second String
	 * @return Levenshtein distance
	 */
	// Source: http://mrfoo.de/archiv/1176-Levenshtein-Distance-in-Java.html ,
	// 20.08.2013
	private static int getLevenshteinDistance(String first, String second) {
		if (first == null || second == null) {
			throw new IllegalArgumentException("Strings must not be null");
		}
		int firstLen = first.length();
		int secondLen = second.length();

		if (firstLen == 0) {
			return secondLen;
		} else if (secondLen == 0) {
			return firstLen;
		}

		int previousCosts[] = new int[firstLen + 1];
		int currentCosts[] = new int[firstLen + 1];
		int costTmp[];

		for (int i = 0; i <= firstLen; i++) {
			previousCosts[i] = i;
		}
		int cost = 0;

		for (int j = 1; j <= secondLen; j++) {
			char sndCh = second.charAt(j - 1);
			currentCosts[0] = j;

			for (int i = 1; i <= firstLen; i++) {
				cost = first.charAt(i - 1) == sndCh ? 0 : 1;
				currentCosts[i] = Math.min(Math.min(currentCosts[i - 1] + 1, previousCosts[i] + 1), previousCosts[i - 1] + cost);
			}

			costTmp = previousCosts;
			previousCosts = currentCosts;
			currentCosts = costTmp;
		}

		return previousCosts[firstLen];
	}

}
