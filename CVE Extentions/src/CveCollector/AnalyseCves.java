package CveCollector;

/**
 * >> This Java program analyzes a folder, which contains several separated XML files extracted of the NVD. <<
 * I/O variables are declared in konfig.java
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
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
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;

import org.apache.lucene.queryparser.classic.ParseException;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import cve.matcher.LuceneIndexCreator;
import cve.matcher.VersionComparator;

public class AnalyseCves {

	private static Vector<String> filelist = new Vector<String>(); // list of
																	// file
																	// directories
	private static Vector<CveItem> itemList = new Vector<CveItem>(); // list of
																		// CVE
																		// items
																		// (abstract
																		// representation
																		// of an
																		// CVE
																		// entry)
	private static String DumpDir = Konfig.CveDump; // directory, which contains
													// CVE XML files FOR CODE
													// TESTING (recommendation:
													// <= 1000 files)
	private static String CveFolder = Konfig.CveFolder; // directory, which
														// contains all CVE XML
														// files for information
														// extraction
	private static String Datatype = Konfig.Datatype; // data type of CVE XML
														// files
	private static String CvePrint = Konfig.CvePrint; // file which should
														// contain the analysis
														// results
	private static boolean Testmode = Konfig.Testmode; // switches the test mode
														// ON/OFF
	private static int MessageTime = Konfig.MessageTime; // default time for
															// displaying a
															// message
	private static PrintWriter pw;
	private int anzFiles = 0;
	private int[] resultCounter = new int[3];

	public static void main(String[] args) {
		AnalyseCves ana = new AnalyseCves();
		String analyseDir = ""; // directory of containing CVE XML files for
								// current analysis
		if (Testmode)
			analyseDir = DumpDir; // checks if test mode is active and sets the
									// current directory
		else
			analyseDir = CveFolder;
		Writer fw;
		Writer bw; // Writer for result text file:
		pw = null;
		try {
			fw = new FileWriter(CvePrint);

			bw = new BufferedWriter(fw);
			pw = new PrintWriter(bw);

			System.out
					.println("\nSelected Folder: "
							+ System.getProperty("user.dir") + "\\"
							+ analyseDir + "\n");
			ana.walk(analyseDir); // analyzes the structure of the current
									// folder and adds all XML files to the file
									// list
			System.out.println("\n" + filelist.size()
					+ " analyzable XML files found in " + analyseDir + "\n"); // message
																				// of
																				// XML
																				// file
																				// number
			// ana.stopfor(); // time of result presentation; default by konfig
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		pw.close(); // extraction process completed
	}

	/**
	 * This method "walks" recursive through the current directory (path) and
	 * collects all analyzable files in the file list.
	 * 
	 * @param path
	 *            path which should be analyzed and found files be saved in
	 *            filelist
	 */
	public void walk(String path) {
		File root = new File(path);
		File[] list = root.listFiles();

		for (File f : list) { // For every file of folder in a directory:
			if (f.isDirectory()) { // Check if it's a dir or file.
				walk(f.getAbsolutePath()); // If it's a dir: recursively call
											// the walk method
				System.out.println("Dir:" + f.getAbsoluteFile()); // and print
																	// the
																	// result.
			} else { // If it's a file:
				String fileresult = f.getAbsoluteFile().toString(); // Check if
																	// it has
																	// the right
																	// data type
																	// (only by
																	// filename).
				String parseName = fileresult.substring(fileresult
						.lastIndexOf("\\"));
				if (parseName.toLowerCase().contains(Datatype)) { // If it has
																	// the right
																	// data
																	// type:
					filelist.add(f.getAbsolutePath()); // Add the absolute path
														// to the filelist
					String line = "";
					String innerText = "";
					FileInputStream fstream; // and create a CVE item by reading
												// the file.
					try {
						fstream = new FileInputStream(f.getAbsolutePath());
						DataInputStream in = new DataInputStream(fstream);
						BufferedReader br = new BufferedReader(
								new InputStreamReader(in));
						while ((line = br.readLine()) != null) {
							innerText += line;
						}

					} catch (Exception e) {
						e.printStackTrace();
					}
					CveItem curItem = new CveItem(innerText);
					resultCounter[1]++;
					this.analyse(curItem); // information extraction of all
											// files in the file list

					// itemList.add(curItem); // Finally add the created CVE
					// item to the item list.
					if (Testmode)
						System.out.println("File:" + f.getAbsoluteFile());
					if (!Testmode && resultCounter[1] % 50 == 0)
						System.out.println(resultCounter[1] + " files read");

				} else
					System.out.println("No XML File:" + f.getAbsoluteFile()); // Message,
																				// if
																				// a
																				// file
																				// does
																				// not
																				// match
																				// to
																				// the
																				// required
																				// data
																				// type.
			}
		}
	}

	/**
	 * The real information extraction part of the program. It analyzes all
	 * found files and saves the results in a text file.
	 * 
	 */
	private void analyse(CveItem item) {
		try {
			if (Testmode)
				System.out.println("------- CVE-Item: " + item.getCVEID()
						+ " -------");
			Vector<Snippet> versions = item
					.getSnippetsWithLogicalUnits("version");
			Vector<NameVersionRelation> relations = new Vector<NameVersionRelation>();
			Iterator<Snippet> versionIt = versions.iterator();
			Snippet curSnip;
			Snippet softwareName;
			while (versionIt.hasNext()) {
				String snippetComment = "";
				curSnip = versionIt.next();
				softwareName = item.searchSoftwareNameBefore(curSnip);
				if (!curSnip.logicalUnitComment().equals(""))
					snippetComment = "    (" + curSnip.logicalUnitComment()
							+ ") ";
				relations.add(new NameVersionRelation(softwareName, curSnip));
				if (Testmode)
					System.out.println(softwareName.getText() + "     Version:"
							+ curSnip.getText() + snippetComment);
			}

			Vector<VersionRange> results = createResult(relations, item);
			StringBuilder output = new StringBuilder();
			for (VersionRange result : results) {
				if (Testmode)
					System.out.println("-> Result: " + result);
				if (!Testmode) {
					if (!Konfig.Logging) {
						output = getMachineReadableOutput(item, result);
					} else {
						output = getHumanReviewOutput(item, result);
					}
					pw.println(output.toString());
				}

			}
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private StringBuilder getHumanReviewOutput(CveItem item, VersionRange result) {
		StringBuilder output = new StringBuilder();
		output.append(item.getCVEID());
		output.append("  ");
		output.append(result.toString());
		output.append("  ");
		output.append(result.cpe());
		return output;
	}

	private StringBuilder getMachineReadableOutput(CveItem item,
			VersionRange result) {
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

	private Vector<VersionRange> createResult(
			Vector<NameVersionRelation> relations, CveItem item) {

		HashSet<NameVersionRelation> interestingRelations = new HashSet<NameVersionRelation>();
		interestingRelations.addAll(relations);

		HashSet<NameVersionRelation> remainingRelations = new HashSet<NameVersionRelation>();
		HashSet<NameVersionRelation> shortestRelations = new HashSet<NameVersionRelation>();
		Vector<VersionRange> relatedRelations = new Vector<VersionRange>();

		if (interestingRelations.size() > 0) {

			relatedRelations = groupRelations(relations, interestingRelations,
					remainingRelations, shortestRelations);

			for (VersionRange versionRange : relatedRelations) {
				List<String> products = getProductList(item);
				String cpename = extractCPE(versionRange, products);
				if (!cpename.isEmpty()) {
					cpename = extractCPEVendor(cpename);
					versionRange.setCPE(cpename);
					// cpe:/a:apache:camel:
					List<String> remaining = fillRemainings(products, cpename);

					if (remaining.size() > 0) {
						List<String> filteredRemainings = LuceneIndexCreator
								.getAllCpesWithVersionPrefix(versionRange
										.shortest().version().getText(),
										remaining);

						if (!versionRange.hasLast()) {
							if (filteredRemainings.size() != 0)
								remaining = filteredRemainings;
							String greatest = "";
							if (versionRange.fixed()) {
								String fix = versionRange.fixedSoftware()
										.getText();
								greatest = VersionComparator
										.getGreatestUnderFix(remaining, fix);
							} else
								greatest = VersionComparator
										.getGreatestMatch(remaining);
							if (!greatest.isEmpty())
								versionRange.setLast(greatest);
						}
					}
				}

			}
		}
		return relatedRelations;
	}

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

	private List<String> getProductList(CveItem item) {
		List<String> products = new ArrayList<String>();
		try {
			NodeList vulnSoftware = (NodeList) item.xPath().evaluate(
					"//entry/vulnerable-software-list/product/text()",
					item.XmlDocument(), XPathConstants.NODESET);
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

	private Vector<VersionRange> groupRelations(
			Vector<NameVersionRelation> relations,
			HashSet<NameVersionRelation> interestingRelations,
			HashSet<NameVersionRelation> remainingRelations,
			HashSet<NameVersionRelation> shortestRelations) {
		Vector<VersionRange> relatedRelations = new Vector<VersionRange>();
		while (interestingRelations.size() > 0) {
			Iterator<NameVersionRelation> relationsIterator = interestingRelations
					.iterator();
			NameVersionRelation shortestRelation = relationsIterator.next();
			shortestRelations.add(shortestRelation);

			while (relationsIterator.hasNext()) {
				NameVersionRelation curRelation = relationsIterator.next();
				if (shortestRelation.trimmedVersion().length() > curRelation
						.trimmedVersion().length()) {
					shortestRelation = curRelation;
					remainingRelations.addAll(shortestRelations);
					shortestRelations.clear();
					shortestRelations.add(curRelation);
				} else if (shortestRelation.trimmedVersion().length() == curRelation
						.trimmedVersion().length()) {
					shortestRelations.add(curRelation);
				} else {
					remainingRelations.add(curRelation);
				}
			}

			interestingRelations.removeAll(shortestRelations);
			boolean sameSoftwareRef = isSameSoftwareRef(shortestRelations,
					shortestRelation);

			if (shortestRelations.size() == relations.size() && sameSoftwareRef) {
				VersionRange versionRange = new VersionRange();
				versionRange.addAll(shortestRelations);
				relatedRelations.add(versionRange);
			} else {
				for (NameVersionRelation curShortestRel : shortestRelations) {
					HashSet<NameVersionRelation> curRelRelation = new HashSet<NameVersionRelation>();
					curRelRelation.add(curShortestRel);

					allocateRemainingRelations(interestingRelations,
							remainingRelations, curShortestRel, curRelRelation);

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

	private boolean isSameSoftwareRef(
			HashSet<NameVersionRelation> shortestRelations,
			NameVersionRelation shortestRelation) {

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

	private void allocateRemainingRelations(
			HashSet<NameVersionRelation> interestingRelations,
			HashSet<NameVersionRelation> remainingRelations,
			NameVersionRelation curShortestRel,
			HashSet<NameVersionRelation> curRelRelation) {
		for (NameVersionRelation curNameVerRel : remainingRelations) {
			if (curNameVerRel.refersSameSoftware(curShortestRel)
					&& (curShortestRel.versionIsMoreGeneral(curNameVerRel) || curShortestRel
							.hasSameSuperversion(curNameVerRel))) {
				curRelRelation.add(curNameVerRel);
				interestingRelations.remove(curNameVerRel);
			}
		}
	}

	/*
	 * Sets a timeout for displaying a message.
	 */
	private void stopfor(int milliseconds) {
		try {
			Thread.sleep(milliseconds);
		} catch (InterruptedException ex) {
			Thread.currentThread().interrupt();
		}
	}

	private void stopfor() {
		int milliseconds = MessageTime;
		stopfor(milliseconds);
	}

	private String extractCPE(VersionRange versionRange, List<String> products) {
		int levenshteinDistance = Integer.MAX_VALUE;
		String cpe = "";
		String softwareName = versionRange.shortest().name().getText() + " "
				+ versionRange.shortest().version().getText();
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
	 * Berechnet den Levenshtein-Abstand zweier Strings
	 * 
	 * @param first
	 *            erster String
	 * @param second
	 *            zweiter String
	 * @return Levenshtein-Abstand
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
				currentCosts[i] = Math
						.min(Math.min(currentCosts[i - 1] + 1,
								previousCosts[i] + 1), previousCosts[i - 1]
								+ cost);
			}

			costTmp = previousCosts;
			previousCosts = currentCosts;
			currentCosts = costTmp;
		}

		return previousCosts[firstLen];
	}

}
