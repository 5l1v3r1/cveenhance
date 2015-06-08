package tud.cve.extractor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Vector;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import tud.cve.data.representation.NameVersionRelation;
import tud.cve.data.representation.Snippet;
import tud.cve.data.representation.VersionRange;

public class AnalyseTest2 {

	AnalyseCves ac;

	@Before
	public void setUp() {
		ac = new AnalyseCves();
	}

	@Test
	public void convertCpeToText_Test1() {
		assertEquals(ac.convertCpeToText("cpe:/a:ibm:java:1.7.0:update_55:windows"), "ibm java");
	}

	@Test
	public void getLevenshteinDistance_Test1() {
		assertEquals(AnalyseCves.getLevenshteinDistance("", ""), 0);
	}

	@Test
	public void getLevenshteinDistance_Test2() {
		assertEquals(AnalyseCves.getLevenshteinDistance("a", ""), 1);
	}

	@Test(expected = IllegalArgumentException.class)
	public void getLevenshteinDistance_Test3() {
		assertTrue(AnalyseCves.getLevenshteinDistance(null, null) == 0);
	}

	@Test
	public void getOutputToXMLFile_Test1() {
		assertEquals(ac.getOutputToXMLFile(new Vector<VersionRange>()), "");
	}

	@Test
	public void getOutputToXMLFile_Test2() {
		assertEquals(ac.getOutputToXMLFile(null), "");
	}

	@Test
	public void getOutputToXMLFile_Test3() {
		CveItem cve = new CveItem(AnalyseCves.getInnerText(new File("resource/testFile1.xml")));
		Vector<Snippet> versions = cve.getSnippetsWithLogicalUnits("version");
		Vector<NameVersionRelation> relations = new Vector<NameVersionRelation>();

		ac.fillRelations(cve, versions, relations);
		assertEquals(
				ac.getOutputToXMLFile(ac.createResult(relations, cve.getCpeList())),
				"\t<ext:ranges>\n\t\t<ext:range>\n\t\t\t<ext:start>cpe:/a:achal_dhir:dual_dhcp_dns_server:1.0</ext:start>\n\t\t</ext:range>\n\t</ext:ranges>");
	}

	@Test
	public void analyse_Test1() {
		ac.analyse(new CveItem(AnalyseCves.getInnerText(new File("resource/testFile1.xml"))), new PrintWriter(
				System.out), new BufferedWriter(new PrintWriter(System.out)));
		assertEquals(ac.resultCounter[1], 1);
	}

	@Test
	public void analyse_Test2() {
		ac.analyse(new CveItem(AnalyseCves.getInnerText(new File("resource/testFile1.xml"))), new PrintWriter(
				System.out), new BufferedWriter(new PrintWriter(System.out)));
		assertEquals(ac.resultCounter[2], 1);
	}

	@Rule
	public TemporaryFolder tempFolder = new TemporaryFolder(new File("resource/test/"));

	@Test
	public void writeFile_Test1() throws IOException {
		File tmp = tempFolder.newFolder("test/");
		Config.OUTPUT_FOLDER = tmp.getAbsolutePath();
		File file = tempFolder.newFile( "test/nvdcve-2.0-2002-enhanced.xml");
		ac.writeNewFile("2002");
		assertTrue(file.exists());
	}

	@Test
	public void analyseCveItem_Test1() {
		ac.analyzeCveItem(new PrintWriter(System.out), new BufferedWriter(new PrintWriter(System.out)), new File(
				"resource/testFile1.xml"));
		assertEquals(ac.resultCounter[2], 1);
	}

	@Test
	public void printResults_Test1() {
		ac.printResults();
	}

	@Test
	public void walk_Test1() throws IOException {
		File tmp = tempFolder.newFolder("test/");
		Config.OUTPUT_FOLDER = tmp.getAbsolutePath();
		File file = tempFolder.newFile("CveTestResult.txt");
		File nvdcve2006 = tempFolder.newFile("test/nvdcve-2.0-2006-enhanced.xml");
		PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(file)));
		ac.walk("resource/", pw);
		assertTrue(nvdcve2006.exists());

	}
	
	static TemporaryFolder tempFolder2;
	
	@After
	public void tearDown(){
		tempFolder2 = tempFolder;
		tempFolder.delete();
	}
	
	 @AfterClass
	    public static void afterClass() {
	        Assert.assertFalse(tempFolder2.getRoot().exists());
	    }

}
