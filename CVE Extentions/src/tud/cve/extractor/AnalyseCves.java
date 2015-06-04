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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Vector;
import java.util.regex.Pattern;

import tud.cpe.preparation.LuceneIndexCreator;
import tud.cve.data.representation.NameVersionRelation;
import tud.cve.data.representation.Snippet;
import tud.cve.data.representation.VersionRange;

/**
 * >> This class contains the extractor main <<
 * 
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */

public class AnalyseCves {

	private static Vector<String> fileDirections = new Vector<String>();

	private int[] resultCounter = new int[5];

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
	 * This method "walks" recursive through the current directory (path) and collects all analyzable files in the file
	 * list.
	 * 
	 * @param path
	 *            path which should be analyzed; files be saved in filelist
	 * 
	 */
	protected void walk(String path, PrintWriter pw) {
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
						bw = new BufferedWriter(new FileWriter(new File(Config.OUTPUT_FOLDER, "nvdcve-2.0-" + year
								+ "-enhanced.xml")));
						bw.write(Config.START_TAGS);
					}
					String parseName = f.getName();
					if (parseName.toLowerCase().endsWith(Config.DATA_TYPE.toLowerCase())) {
						fileDirections.add(f.getAbsolutePath());
						StringBuilder innerText = new StringBuilder();
						try {
							BufferedReader br = new BufferedReader(new FileReader(f));
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
						if (Config.LOGGING)
							System.out.println(curItem.getCVEID());
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

		System.out.println("\nCVE entries: " + resultCounter[0] + "\nCVE entries with information: " + resultCounter[4]
				+ "\nCVE entries with first information: " + resultCounter[1] + "\nCVE entries with last information: "
				+ resultCounter[2] + "\nCVE entries with fix information: " + resultCounter[3] + "\n");
	}

	/**
	 * This method is used to extract information of a single CVE entry.
	 * 
	 */
	protected void analyse(CveItem item, PrintWriter pw, BufferedWriter bw) {
		try {
			if (Config.TEST_MODE)
				System.out.println("------- CVE-Item: " + item.getCVEID() + " -------");
			Vector<Snippet> versions = item.getSnippetsWithLogicalUnits("version");
			Vector<NameVersionRelation> relations = new Vector<NameVersionRelation>();

			fillRelations(item, versions, relations);

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
				if (!result.firstDetectedVersion().equals(""))
					hasFirst = true;
				if (!result.lastDetectedVersion().isEmpty())
					hasLast = true;
				if (!result.fixedVersion().isEmpty())
					hasFix = true;
				if (Config.TEST_MODE)
					System.out.println("-> Result: " + result);
				else {
					if (!Config.LOGGING) {
						output = result.getMachineReadableOutput(item.getCVEID());
					} else {
						output = result.getHumanReviewOutput(item.getCVEID());
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
			if (hasFirst || hasLast || hasFix)
				resultCounter[4]++;
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected void fillRelations(CveItem item, Vector<Snippet> versions, Vector<NameVersionRelation> relations) {
		for (Snippet curSnip : versions) {
			String snippetComment = "";
			Snippet softwareName = item.searchSoftwareNameBefore(curSnip);
			if (!curSnip.logicalUnitComment().isEmpty())
				snippetComment = "    (" + curSnip.logicalUnitComment() + ") ";
			if (!softwareName.getText().isEmpty() && Pattern.matches(".*\\d+.*", curSnip.getText()))
				relations.add(new NameVersionRelation(softwareName, curSnip));
			if (Config.TEST_MODE)
				System.out.println(softwareName.getText() + "     Version:" + curSnip.getText() + snippetComment);
		}
	}

	/**
	 * Creates an XML Output
	 * 
	 * @param results
	 *            extracted version ranges
	 * @return XML output string
	 */

	protected String getOutputToXMLFile(Vector<VersionRange> results) {
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
	 * Creates the result of a single extraction
	 * 
	 * @param relations
	 *            all found NameVersionRelations of a CVE entry
	 * @param item
	 *            the corresponding CVE entry
	 * @return resulting version ranges
	 */
	public Vector<VersionRange> createResult(Vector<NameVersionRelation> relations, CveItem item) {

		HashSet<NameVersionRelation> interestingRelations = new HashSet<NameVersionRelation>();
		interestingRelations.addAll(relations);

		HashSet<NameVersionRelation> remainingRelations = new HashSet<NameVersionRelation>();
		HashSet<NameVersionRelation> shortestRelations = new HashSet<NameVersionRelation>();
		Vector<VersionRange> relatedRelations = new Vector<VersionRange>();

		if (interestingRelations.size() > 0) {

			relatedRelations = groupRelations(relations, interestingRelations, remainingRelations, shortestRelations);

			for (VersionRange versionRange : relatedRelations) {
				List<String> cpes = item.getCpeList();
				if (cpes.size() > 0) {
					Set<String> products = new HashSet<String>();
					for (String cpe : cpes) {
						products.add(extractCPEProduct(cpe));
					}
					String cpename = (String) products.toArray()[0];
					if (products.size() > 1)
						cpename = extractCPE(versionRange, cpes);
					if (!cpename.isEmpty()) {
						cpename = extractCPEProduct(cpename);
						versionRange.setCPE(cpename);
						// cpe:/a:apache:camel:
						List<String> remaining = fillRemainings(cpes, cpename);

						if (remaining.size() > 0) {
							List<String> filteredRemainings = LuceneIndexCreator.getAllCpesWithVersionPrefix(
									versionRange.shortest().version().getText(), remaining);

							if (!versionRange.hasLast()) {
								if (filteredRemainings.size() != 0)
									remaining = filteredRemainings;
								String greatest = "";
								String versionText = versionRange.shortest().version().getText();
								if (!versionRange.fixed() && versionRange.hasFirst() && versionText.endsWith(".x"))
									greatest = VersionComparator.getGreatestMatch(remaining, cpename,
											versionText.substring(0, versionText.length() - 2));
								if (!greatest.isEmpty())
									versionRange.setLast(greatest);
							}

						}
					}
				}
			}
		}
		relatedRelations = checkValidity(relatedRelations);
		return relatedRelations;
	}

	private Vector<VersionRange> checkValidity(Vector<VersionRange> relatedRelations) {
		Vector<VersionRange> relatedResultRelations = new Vector<VersionRange>();
		for (VersionRange curResultRange : relatedRelations) {
			String firstSoftware = curResultRange.firstDetectedVersion();
			if (firstSoftware.contains(" "))
				firstSoftware = firstSoftware.substring(0, firstSoftware.indexOf(" "));
			String lastSoftware = curResultRange.lastDetectedVersion();
			if (lastSoftware.contains(" "))
				lastSoftware = lastSoftware.substring(0, lastSoftware.indexOf(" "));
			String fixedSoftware = curResultRange.fixedVersion();
			if (fixedSoftware.contains(" "))
				fixedSoftware = fixedSoftware.substring(0, fixedSoftware.indexOf(" "));
			boolean lastAndFix = false;
			if (!fixedSoftware.isEmpty() && !lastSoftware.isEmpty())
				lastAndFix = true;
			if (!lastAndFix
					&& !curResultRange.getSoftwareName().isEmpty()
					&& (!firstSoftware.isEmpty() || !lastSoftware.isEmpty() || !fixedSoftware.isEmpty())
					&& (firstSoftware.isEmpty() || (firstSoftware.toLowerCase().matches("[\\d]+[\\p{Punct}\\w]*") && firstSoftware
							.replaceAll("\\d", "").length() != firstSoftware.length()))
					&& (lastSoftware.isEmpty() || (lastSoftware.toLowerCase().matches("[\\d]+[\\p{Punct}\\w]*") && lastSoftware
							.replaceAll("\\d", "").length() != lastSoftware.length()))
					&& (fixedSoftware.isEmpty() || (fixedSoftware.toLowerCase().matches("[\\d]+[\\p{Punct}\\w]*") && fixedSoftware
							.replaceAll("\\d", "").length() != fixedSoftware.length())))
				relatedResultRelations.add(curResultRange);
			else {
				Exception e = new Exception("Final validity check failed: " + curResultRange.getSoftwareName() + " "
						+ firstSoftware + ", " + lastSoftware + ", " + fixedSoftware);
				try {
					throw e;
				} catch (Exception e1) {
					e1.printStackTrace();
				}
			}
		}
		return relatedResultRelations;
	}

	/**
	 * extracts the vendor part of a CPEstring
	 * 
	 * @param cpename
	 *            complete CPE string
	 * @return vendor part of CPE
	 */
	public static String extractCPEProduct(String cpename) {
		String[] split = cpename.split(":");
		cpename = "";
		for (int i = 0; i < 4; i++) {
			cpename += split[i] + ":";
		}
		return cpename;
	}

	private List<String> fillRemainings(List<String> cpes, String cpename) {
		List<String> remaining = new ArrayList<String>();
		for (String product : cpes) {
			if (product.startsWith(cpename))
				remaining.add(product);
		}
		return remaining;
	}

	/**
	 * Groups NameVersionRelations to VersionRanges
	 * 
	 * @param relations
	 *            all relations
	 * @return A vector of version ranges
	 */
	private Vector<VersionRange> groupRelations(Vector<NameVersionRelation> relations,
			HashSet<NameVersionRelation> interestingRelations, HashSet<NameVersionRelation> remainingRelations,
			HashSet<NameVersionRelation> shortestRelations) {
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

			if (shortestRelations.size() == relations.size()) {

				for (NameVersionRelation curShortestRel : shortestRelations) {
					Iterator<VersionRange> versionRangeIterator = relatedRelations.iterator();
					boolean alreadyAdded = false;
					while (versionRangeIterator.hasNext()) {
						VersionRange curRange = versionRangeIterator.next();
						if (curShortestRel.refersSameSoftware(curRange.shortest())) {
							if (curShortestRel.hasSameSuperversion(curRange.shortest())) {
								curRange.add(curShortestRel);
								alreadyAdded = true;
								continue;
							}
						}
					}
					if (!alreadyAdded) {
						VersionRange versionRange = new VersionRange();
						versionRange.add(curShortestRel);
						relatedRelations.add(versionRange);
					}
				}
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

	private void allocateRemainingRelations(HashSet<NameVersionRelation> interestingRelations,
			HashSet<NameVersionRelation> remainingRelations, NameVersionRelation curShortestRel,
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

	/**
	 * Returns the most alike cpe string
	 * 
	 * @param versionRange
	 * @param cpes
	 * @return most alike cpe string
	 */
	private String extractCPE(VersionRange versionRange, List<String> cpes) {
		Map<String, String> cpeResolutions = new HashMap<String, String>();
		for (String cpe : cpes) {
			String resolution;
			try {
				resolution = LuceneIndexCreator.findTitle(cpe);

				if (resolution.length() > 0) {
					cpeResolutions.put(resolution, cpe);
				} else {
					cpeResolutions.put(convertCpeToText(cpe), cpe);
				}
			} catch (Exception e) {
				cpeResolutions.put(convertCpeToText(cpe), cpe);
			}
		}
		int levenshteinDistance = Integer.MAX_VALUE;
		String cpe = "";
		String softwareName = versionRange.shortest().name().getText();
		int currentdistance;
		for (Entry<String, String> entry : cpeResolutions.entrySet()) {
			currentdistance = getLevenshteinDistance(entry.getKey(), softwareName);
			if (currentdistance < levenshteinDistance) {
				cpe = entry.getValue();
				levenshteinDistance = currentdistance;
			}
		}
		return cpe;
	}

	public String convertCpeToText(String cpe) {
		String[] split = cpe.split(":");
		String result = split[2] + " " + split[3];
		boolean isLastEmptySpace = false;
		String line = "";
		for (int i = 0; i < result.length(); i++) {
			char c = result.charAt(i);
			if (Character.isLetter(c)) {
				line += c;
				isLastEmptySpace = false;
			} else if (!isLastEmptySpace) {
				line += " ";
				isLastEmptySpace = true;
			}
		}
		return line.trim().toLowerCase();
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
				currentCosts[i] = Math.min(Math.min(currentCosts[i - 1] + 1, previousCosts[i] + 1),
						previousCosts[i - 1] + cost);
			}

			costTmp = previousCosts;
			previousCosts = currentCosts;
			currentCosts = costTmp;
		}

		return previousCosts[firstLen];
	}

}
