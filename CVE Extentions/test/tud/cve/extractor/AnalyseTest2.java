package tud.cve.extractor;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.util.Vector;

import org.junit.Before;
import org.junit.Test;

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
}
