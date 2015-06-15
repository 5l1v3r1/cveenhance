package tud.cve.extractor;

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.Writer;
import java.util.ArrayList;
import java.util.Vector;
import java.util.Iterator;

import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import tud.cve.data.representation.NameVersionRelation;
import tud.cve.data.representation.Snippet;
import tud.cve.data.representation.VersionRange;

public class AnalyseTest {

	private static Vector<VersionRange> desiredResults = new Vector<VersionRange>();
	private static Vector<String> allFixes = new Vector<String>();
	private static Vector<String> allCveIDs = new Vector<String>();
	private static CveItem[] testItems = new CveItem[10];

	private static String intoString = "  <entry><vuln:vulnerable-configuration id=\"http://nvd.nist.gov/\"><cpe-lang:logical-test operator=\"OR\" negate=\"false\"></cpe-lang:logical-test></vuln:vulnerable-configuration><vuln:vulnerable-software-list>";
	private static String secondString = " </vuln:vulnerable-software-list><vuln:cve-id>";
	private static String thirdString = "</vuln:cve-id><vuln:published-datetime>1999-12-30T00:00:00.000-05:00</vuln:published-datetime><vuln:last-modified-datetime>2010-12-16T00:00:00.000-05:00</vuln:last-modified-datetime><vuln:cvss><cvss:base_metrics><cvss:score>5.0</cvss:score><cvss:access-vector>NETWORK</cvss:access-vector><cvss:access-complexity>LOW</cvss:access-complexity><cvss:authentication>NONE</cvss:authentication><cvss:confidentiality-impact>NONE</cvss:confidentiality-impact><cvss:integrity-impact>NONE</cvss:integrity-impact><cvss:availability-impact>PARTIAL</cvss:availability-impact><cvss:source>http://nvd.nist.gov</cvss:source><cvss:generated-on-datetime>2004-01-01T00:00:00.000-05:00</cvss:generated-on-datetime></cvss:base_metrics></vuln:cvss><vuln:cwe id=\"CWE-20\"/><vuln:references reference_type=\"UNKNOWN\" xml:lang=\"en\"><vuln:source>OSVDB</vuln:source><vuln:reference href=\"http://www.osvdb.org/5707\" xml:lang=\"en\">5707</vuln:reference></vuln:references><vuln:references reference_type=\"UNKNOWN\" xml:lang=\"en\"><vuln:source>CONFIRM</vuln:source><vuln:reference href=\"http://www.openbsd.org/errata23.html#tcpfix\" xml:lang=\"en\">http://www.openbsd.org/errata23.html#tcpfix</vuln:reference></vuln:references><vuln:summary>";
	private static String lastString = " </vuln:summary></entry>";

	@Before
	public void clearAll() {
		clearCurrentDesiredResult();
	}

	// 1. Slot: Vuln-Softwarelist // 2.Slot: CVE-ID //3. Slot: Vuln.-Beschreibung

	@Test
	public void beforeKeywordTest() {
		try {

			testItems[0] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:macromedia:flashplayer:7.2</vuln:product>"
							+ secondString
							+ "CVE-2000-0000"
							+ thirdString
							+ "In the Macromedia Flash Player before 7.3 a cross side vunerability occours. It is often used to gather bank account data. "
							+ lastString);
			addPartResult("Macromedia Flash Player", "", "", "7.3", "cpe:/a:macromedia:flashplayer:", "CVE-2000-0000");
			assertTrue(checkItemResult(testItems[0], "before keyword check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void beforeAndEarlierTest() {
		try {

			testItems[0] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:macromedia:flashplayer:7.2</vuln:product>"
							+ secondString
							+ "CVE-2000-0000"
							+ thirdString
							+ "In the Macromedia Flash Player 7.2.3 and earlier before 7.2.4 a cross side vunerability occours. It is often used to gather bank account data. "
							+ lastString);
			addPartResult("Macromedia Flash Player", "", "", "7.2.4", "cpe:/a:macromedia:flashplayer:", "CVE-2000-0000");
			assertTrue(checkItemResult(testItems[0], "double information before/earlier check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void earlierKeywordTest() {
		try {
			testItems[1] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:macromedia:flashplayer:7.1</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.2</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.0</vuln:product>"
							+ secondString
							+ "CVE-2000-0001"
							+ thirdString
							+ "In the Macromedia Flash Player 7.2 and earlier a cross side vunerability occours. It is often used to gather bank account data. "
							+ lastString);
			addPartResult("Macromedia Flash Player", "", "7.2", "", "cpe:/a:macromedia:flashplayer:", "CVE-2000-0001");
			assertTrue(checkItemResult(testItems[1], "earlier keyword check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void multiSoftwareTest() {
		try {
			testItems[2] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:adobe:flashplayer:4.3.0</vuln:product><vuln:product>cpe:/a:adobe:flashplayer:4.3.1</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.1</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.2</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.0</vuln:product>"
							+ secondString
							+ "CVE-2000-0002"
							+ thirdString
							+ "In the Macromedia Flash Player 7.2 and earlier and Adobe Flash Player before 4.3.2 a cross side vunerability occours. It is often used to gather bank account data. "
							+ lastString);
			addPartResult("Macromedia Flash Player", "", "7.2", "", "cpe:/a:macromedia:flashplayer:", "CVE-2000-0002");
			addPartResult("Adobe Flash Player", "", "", "4.3.2", "cpe:/a:adobe:flashplayer:", "CVE-2000-0002");
			assertTrue(checkItemResult(testItems[2], "multi software check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void multiVersionTest1() {
		try {
			testItems[3] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:macromedia:flashplayer:7.2.3</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.2.4</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:7.2.7</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:8.3.3</vuln:product><vuln:product>cpe:/a:macromedia:flashplayer:8.3.2</vuln:product>"
							+ secondString
							+ "CVE-2000-0003"
							+ thirdString
							+ "In the Macromedia Flash Player 7.2 before 7.2.8 and in 8.3.x before 8.3.4 a cross side vunerability occours. It is often used to gather bank account data. "
							+ lastString);
			addPartResult("Macromedia Flash Player", "7.2", "", "7.2.8", "cpe:/a:macromedia:flashplayer:",
					"CVE-2000-0003");
			addPartResult("Macromedia Flash Player", "8.3.0", "", "8.3.4", "cpe:/a:macromedia:flashplayer:",
					"CVE-2000-0003");
			assertTrue(checkItemResult(testItems[3], "multi version check 1"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void multiVersionTest2() {
		try {
			testItems[4] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.1</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.2</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.3</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:4.2.4</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:4.2.3</vuln:product>"
							+ secondString
							+ "CVE-2000-0004"
							+ thirdString
							+ "This introducing sentence is very confusing for humans but should be handled by the PC. Maybe a second sentence my be even more confusing for us humans. In the Multimedia Center of the Mozilla Software Testsuite 3.2.x through 3.2.3 and 4.2.x before 4.2.5 a cross CSS attack is possible. It is often used to gather you personal Backgammon Arcade game data. "
							+ lastString);
			addPartResult("Mozilla Software Testsuite", "3.2.0", "3.2.3", "", "cpe:/a:mozilla:softwaretestsuite:",
					"CVE-2000-0004");
			addPartResult("Mozilla Software Testsuite", "4.2.0", "", "4.2.5", "cpe:/a:mozilla:softwaretestsuite:",
					"CVE-2000-0004");
			assertTrue(checkItemResult(testItems[4], "multi version check 2"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void specialVersionTest() {
		try {
			testItems[5] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.1</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.2</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.3</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:4.2.4</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:4.2.3</vuln:product>"
							+ secondString
							+ "CVE-2000-0004"
							+ thirdString
							+ "This introducing sentence is very confusing for humans but should be handled by the PC. Maybe a second sentence my be even more confusing for us humans. In the Multimedia Center of the Mozilla Software Testsuite 3.2.x through 3.2.3 update 2 and 4.2.x before 4.2.5 build 2233 a cross CSS attack is possible. It is often used to gather you personal Backgammon Arcade game data. "
							+ lastString);
			addPartResult("Mozilla Software Testsuite", "3.2.0", "3.2.3 update 2", "",
					"cpe:/a:mozilla:softwaretestsuite:", "CVE-2000-0004");
			addPartResult("Mozilla Software Testsuite", "4.2.0", "", "4.2.5 build 2233",
					"cpe:/a:mozilla:softwaretestsuite:", "CVE-2000-0004");
			assertTrue(checkItemResult(testItems[5], "special version check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void versionRangeRecognitionTest() {
		try {
			testItems[6] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.1</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.2</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.3</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:4.2.4</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:4.2.3</vuln:product>"
							+ secondString
							+ "CVE-2000-0005"
							+ thirdString
							+ "In the Multimedia Center of the Mozilla Software Testsuite 3.2.1, 3.2.2 and 3.2.3 update 2 a cross CSS attack is possible. It is often used to gather you personal Backgammon Arcade game data. "
							+ lastString);
			addPartResult("Mozilla Software Testsuite", "3.2.1", "3.2.1", "", "cpe:/a:mozilla:softwaretestsuite:",
					"CVE-2000-0005");
			addPartResult("Mozilla Software Testsuite", "3.2.2", "3.2.2", "", "cpe:/a:mozilla:softwaretestsuite:",
					"CVE-2000-0005");
			addPartResult("Mozilla Software Testsuite", "3.2.3 update 2", "3.2.3 update 2", "",
					"cpe:/a:mozilla:softwaretestsuite:", "CVE-2000-0005");

			assertTrue(checkItemResult(testItems[6], "version range recognition check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	@Test
	public void softwareNameRecognitionTest() {
		try {
			testItems[7] = new CveItem(
					intoString
							+ "<vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.1</vuln:product><vuln:product>cpe:/a:adobe:reader:7.3</vuln:product><vuln:product>cpe:/a:mozilla:softwaretestsuite:3.2.0</vuln:product><vuln:product>cpe:/a:mozilla:firefox:3.2.3</vuln:product><vuln:product>cpe:/a:mozilla:firefox:3.2.2</vuln:product>"
							+ secondString
							+ "CVE-2000-0006"
							+ thirdString
							+ "In Mozilla Software Testsuite 3.2.1, Adobe Reader, Mozilla Firefox 3.2.2 and 3.2.3 and a cross CSS attack is possible. It is often used to gather you personal Backgammon Arcade game data. "
							+ lastString);
			addPartResult("Mozilla Software Testsuite", "3.2.1", "3.2.1", "", "cpe:/a:mozilla:softwaretestsuite:",
					"CVE-2000-0006");
			addPartResult("Mozilla Firefox", "3.2.2", "3.2.2", "", "cpe:/a:mozilla:firefox:", "CVE-2000-0006");
			addPartResult("Mozilla Firefox", "3.2.3", "3.2.3", "", "cpe:/a:mozilla:firefox:", "CVE-2000-0006");
			assertTrue(checkItemResult(testItems[7], "software name recognition check"));
		} catch (Exception e) {
			e.printStackTrace();
			fail("AnalyseTest failed: thrown exception");
		}
	}

	// -----------------------------------------

	private void addPartResult(String softwareName, String versionStart, String versionEnd, String versionFix,
			String cpe, String cveID) {
		VersionRange curVersionRange = new VersionRange();
		curVersionRange.updateSoftwareName(softwareName);
		curVersionRange.setCPE(cpe);
		curVersionRange.setFirst(versionStart);
		curVersionRange.setLast(versionEnd);
		desiredResults.add(curVersionRange);
		allFixes.add(versionFix);
		allCveIDs.add(cveID);
	}

	private void clearCurrentDesiredResult() {
		desiredResults.removeAllElements();
		allFixes.clear();
		allCveIDs.removeAllElements();
	}

	private boolean checkItemResult(CveItem testItem, String testTitle) {

		boolean returnBool = true;
		String extractedCveID = testItem.getCVEID();

		AnalyseCves analyseTestUnit = new AnalyseCves();
		Vector<Snippet> versions = testItem.getSnippetsWithLogicalUnits("version");
		Vector<NameVersionRelation> relations = new Vector<NameVersionRelation>();

		AnalyseCves.fillRelations(testItem, versions, relations);
		Vector<VersionRange> results = analyseTestUnit.createResult(relations, testItem.getCpeList());

		System.out.println("===== Analyzing " + extractedCveID + " \"" + testTitle + "\" =====");
		Iterator<String> fixIterator = allFixes.iterator();

		for (VersionRange desiredResult : desiredResults) {
			String fix = fixIterator.next();
			int resultCheckedCounter = 0;
			System.out.println(desiredResult.getSoftwareName() + " (" + desiredResult.firstDetectedVersion() + "->"
					+ desiredResult.lastDetectedVersion() + "), fix: " + fix + ":");
			boolean partResultCorrect = false;

			for (VersionRange result : results) {
				System.out
						.println("\nComparing desired result with extracted result no. " + (resultCheckedCounter + 1));
				if (desiredResult.getSoftwareName().equals(result.getSoftwareName())
						&& desiredResult.firstDetectedVersion().equals(result.firstDetectedVersion())
						&& desiredResult.lastDetectedVersion().equals(result.lastDetectedVersion())
						&& desiredResult.cpe().equals(result.cpe())) {
					System.out.println("Ckecked: SW-Name OK, First OK, Last OK, CPE OK");
					if (result.fixedVersion().equals(fix)) {
						System.out.println("Note: Fix OK");
						if (extractedCveID.equals(allCveIDs.get(resultCheckedCounter))) {
							partResultCorrect = true;
							break;
						} else
							System.out.println("Warning: CVE-ID not correct");
					} else
						System.out.println("Warning: Fix " + result.fixedVersion() + " not correct. Desired: " + fix);
				} else {
					String failString = "";
					System.out.print("Checked: ");
					if (!desiredResult.getSoftwareName().equals(result.getSoftwareName())) {
						System.out.print("SW-Name NG,");
						failString += "SW-Name desired: " + desiredResult.getSoftwareName() + ", found: "
								+ result.getSoftwareName() + "\n";
					} else
						System.out.print("SW-Name OK,");

					if (!desiredResult.firstDetectedVersion().equals(result.firstDetectedVersion())) {
						System.out.print(" First NG,");
						failString += "First desired: " + desiredResult.firstDetectedVersion() + ", found: "
								+ result.firstDetectedVersion() + "\n";
					} else
						System.out.print(" First OK,");

					if (!desiredResult.lastDetectedVersion().equals(result.lastDetectedVersion())) {
						System.out.print(" Last NG,");
						failString += "Last desired: " + desiredResult.lastDetectedVersion() + ", found: "
								+ result.lastDetectedVersion() + "\n";
					} else
						System.out.print(" Last OK,");

					if (!desiredResult.cpe().equals(result.cpe())) {
						System.out.println(" CPE NG");
						failString += "CPE desired: " + desiredResult.cpe() + ", found: " + result.cpe() + "\n";
					} else
						System.out.println(" CPE OK");
					if (!failString.isEmpty())
						System.out.print(failString);
				}
				resultCheckedCounter++;
			}
			if (partResultCorrect)
				System.out.println("Check: OK \n");
			else {
				System.out.println("Check: FAILED\n");
				returnBool = false;
			}
		}
		clearCurrentDesiredResult();
		if (returnBool)
			System.out.println("=> " + testTitle + ": ==== OK ====\n");
		else
			System.out.println("=> " + testTitle + ": !!!!! FAILED !!!!!\n");
		return returnBool;
	}

}
