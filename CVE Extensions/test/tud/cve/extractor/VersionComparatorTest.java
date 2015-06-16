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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

public class VersionComparatorTest {
	String[] cpes;

	@Before
	public void setUp() {
		cpes = new String[] { "cpe:/a:ibm:java:7.0.0.0",
				"cpe:/a:ibm:java:7.0.1.0", "cpe:/a:ibm:java:7.0.2.0",
				"cpe:/a:ibm:java:7.0.3.0", "cpe:/a:ibm:java:7.0.4.0",
				"cpe:/a:ibm:java:7.0.4.1", "cpe:/a:ibm:java:7.0.4.2",
				"cpe:/a:ibm:java:5.0.14.0", "cpe:/a:ibm:java:5.0.15.0",
				"cpe:/a:ibm:java:5.0.11.1", "cpe:/a:ibm:java:5.0.0.0",
				"cpe:/a:ibm:java:5.0.11.2", "cpe:/a:ibm:java:5.0.12.0",
				"cpe:/a:ibm:java:5.0.12.1", "cpe:/a:ibm:java:5.0.12.2",
				"cpe:/a:ibm:java:5.0.12.3", "cpe:/a:ibm:java:5.0.12.4",
				"cpe:/a:ibm:java:5.0.12.5", "cpe:/a:ibm:java:5.0.13.0",
				"cpe:/a:ibm:java:5.0.16.2", "cpe:/a:oracle:jre:5.0.16.1",
				"cpe:/a:oracle:jre:5.0.16.0", "cpe:/a:oracle:jre:5.0.11.0",
				"cpe:/a:ibm:java:6.0.1.0", "cpe:/a:ibm:java:6.0.11.0",
				"cpe:/a:ibm:java:6.0.10.1", "cpe:/a:ibm:java:6.0.0.0",
				"cpe:/a:ibm:java:6.0.12.0", "cpe:/a:ibm:java:6.0.2.0",
				"cpe:/a:ibm:java:6.0.3.0", "cpe:/a:ibm:java:6.0.4.0",
				"cpe:/a:ibm:java:6.0.5.0", "cpe:/a:ibm:java:6.0.7.0",
				"cpe:/a:ibm:java:6.0.6.0", "cpe:/a:ibm:java:6.0.8.1",
				"cpe:/a:ibm:java:6.0.8.0", "cpe:/a:sun:jre:6.0.9.1",
				"cpe:/a:sun:jre:6.0.9.0", "cpe:/a:ibm:java:6.0.10.0",
				"cpe:/a:ibm:java:6.0.9.2", "cpe:/a:ibm:java:6.0.13.0",
				"cpe:/a:ibm:java:6.0.13.1", "cpe:/a:ibm:java:6.0.13.2" };
	}

	@Test
	public void compareTo_Test1() {
		String version1 = cpes[0].split(":")[4];
		String version2 = cpes[1].split(":")[4];
		assertEquals(VersionComparator.compareTo(version1, version2), -1);
	}

	@Test
	public void compareTo_Test2() {
		String version1 = cpes[0].split(":")[4];
		String version2 = cpes[1].split(":")[4];
		assertEquals(VersionComparator.compareTo(version2, version1), 1);
	}

	@Test
	public void compareTo_Test3() {
		String version = cpes[1].split(":")[4];
		assertEquals(VersionComparator.compareTo(version, version), 0);
	}

	@Test
	public void convertExtToNumbers_Test1() {
		String ext1 = "build 1";
		assertEquals(VersionComparator.convertExtToNumbers(ext1), "1");
	}
	
	@Test
	public void convertExtToNumbers_Test2() {
		String ext1 = "build 1.12.13_5";
		assertEquals(VersionComparator.convertExtToNumbers(ext1), "1 12 13 5");
	}
	
	@Test
	public void convertExtToNumbers_Test3() {
		String ext1 = "build 1.12.13_5:update_16";
		assertEquals(VersionComparator.convertExtToNumbers(ext1), "1 12 13 5 16");
	}
	
	@Test
	public void convertExtToNumbers_Test4() {
		String ext1 = "";
		assertEquals(VersionComparator.convertExtToNumbers(ext1), "");
	}
	
	@Test
	public void convertExtToNumbers_Test5() {
		String ext1 = null;
		assertEquals(VersionComparator.convertExtToNumbers(ext1), "");
	}
	
	@Test
	public void getGreatestMatch_Test1(){
		List<String> cpeList=Arrays.asList(cpes);
		assertEquals(VersionComparator.getGreatestMatch(cpeList, "cpe:/a:ibm:java", "6.0"),"cpe:/a:ibm:java:6.0.13.2");
	}
	
	@Test
	public void getGreatestMatch_Test2(){
		List<String> cpeList=Arrays.asList(cpes);
		assertEquals(VersionComparator.getGreatestMatch(cpeList, "cpe:/a:sun:jre", "6.0"),"cpe:/a:sun:jre:6.0.9.1");
	}
	
	@Test
	public void getGreatestMatch_Test3(){
		List<String> cpeList=Arrays.asList(cpes);
		assertEquals(VersionComparator.getGreatestMatch(cpeList, "cpe:/a:ibm:java", "5"),"cpe:/a:ibm:java:5.0.16.2");
	}
	
	@Test
	public void getGreatestMatch_Test4(){
		List<String> cpeList=Arrays.asList(cpes);
		assertEquals(VersionComparator.getGreatestMatch(cpeList, "cpe:/a:ibm:java", "5.0.14"),"cpe:/a:ibm:java:5.0.14.0");
	}
	
	@Test
	public void getGreatestMatch_Test5(){
		List<String> cpeList=Arrays.asList(cpes);
		assertEquals(VersionComparator.getGreatestMatch(cpeList, "cpe:/a:oracle:jre", "5.0"),"cpe:/a:oracle:jre:5.0.16.1");
	}
	
	@Test
	public void getGreatestMatch_Test6(){
		
		List<String> cpeList=new ArrayList<String>();
		for(String cpe:cpes){
			cpeList.add(cpe);
		}
		cpeList.add("cpe:/a:oracle:jre:5.0.16.1:build_1");
		assertEquals(VersionComparator.getGreatestMatch(cpeList, "cpe:/a:oracle:jre", "5.0"),"cpe:/a:oracle:jre:5.0.16.1:build_1");
	}
	
	@Test
	public void getGreatestMatch_Test7(){
		
		List<String> cpeList=new ArrayList<String>();
		for(String cpe:cpes){
			cpeList.add(cpe);
		}
		cpeList.add("cpe:/a:oracle:jre:5.0.16.1:build_1");
		cpeList.add("cpe:/a:oracle:jre:5.0.16.1:build_2");
		assertEquals(VersionComparator.getGreatestMatch(cpeList, "cpe:/a:oracle:jre", "5.0"),"cpe:/a:oracle:jre:5.0.16.1:build_2");
	}
}
