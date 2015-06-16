package tud.cve.extractor;

/*
 * This work is licensed under the MIT License. 
 * The MIT License (MIT)

 * Copyright (c) 2015  Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), 
 * Ben Hermann (STG), Technische Universität Darmstadt

 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:

 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.

 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 */

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
		assertEquals(AnalyseCves.getOutputToXMLFile(new Vector<VersionRange>()), "");
	}

	@Test
	public void getOutputToXMLFile_Test2() {
		assertEquals(AnalyseCves.getOutputToXMLFile(null), "");
	}

	@Test
	public void getOutputToXMLFile_Test3() {
		CveItem cve = new CveItem(AnalyseCves.getInnerText(new File("resource/testFile1.xml")));
		Vector<Snippet> versions = cve.getSnippetsWithLogicalUnits("version");
		Vector<NameVersionRelation> relations = new Vector<NameVersionRelation>();

		AnalyseCves.fillRelations(cve, versions, relations);
		assertEquals(
				AnalyseCves.getOutputToXMLFile(ac.createResult(relations, cve.getCpeList())),
				"\t<ext:ranges>\n\t\t<ext:range>\n\t\t\t<ext:start>cpe:/a:achal_dhir:dual_dhcp_dns_server:1.0</ext:start>\n\t\t\t<ext:end>cpe:/a:achal_dhir:dual_dhcp_dns_server:1.0</ext:end>\n\t\t</ext:range>\n\t</ext:ranges>");
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
