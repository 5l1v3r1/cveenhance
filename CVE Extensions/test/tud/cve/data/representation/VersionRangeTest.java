package tud.cve.data.representation;

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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;

import org.junit.Before;
import org.junit.Test;

import tud.cve.extractor.LogicalUnit;

public class VersionRangeTest {

	VersionRange last;
	VersionRange fix;

	@Before
	public void setUp() {
		Snippet name = new Snippet("Macro Media Flash Player");
		Snippet version = new Snippet("3.1");
		version.setLogicalUnit(new LogicalUnit("version"));
		version.setLogicalUnitComment("first detected vulnerability");
		NameVersionRelation nvr = new NameVersionRelation(name, version);
		Snippet version2 = new Snippet("3.2");
		version2.setLogicalUnit(new LogicalUnit("version"));
		version2.setLogicalUnitComment("last detected vulnerability");
		nvr.setVersion(version2);

		Snippet version3 = new Snippet("3.3");
		version3.setLogicalUnit(new LogicalUnit("version"));
		version3.setLogicalUnitComment("fixed");
		fix = new VersionRange(new NameVersionRelation(name, version3));
		last = new VersionRange(nvr);
	}

	@Test
	public void lastXMLTag_Test1() {
		last = new VersionRange();
		assertEquals(last.lastXMLTag(), "");
	}

	@Test
	public void lastXMLTag_Test2() {
		assertEquals(last.lastXMLTag(), "\t\t\t<ext:end>3.2</ext:end>");
	}

	@Test
	public void lastXMLTag_Test3() {
		assertEquals(fix.lastXMLTag(), "");
	}

	@Test
	public void fixXMLTag_Test1() {
		assertEquals(fix.fixedXMLTag(), "\t\t\t<ext:fix>3.3</ext:fix>");
	}

	@Test
	public void fixXMLTag_Test2() {
		assertEquals(last.fixedXMLTag(), "");
	}

	@Test
	public void hasVersionData_Test1() {
		assertTrue(last.hasVersionData());
	}

	@Test
	public void hasVersionData_Test2() {
		assertTrue(fix.hasVersionData());
	}

	@Test
	public void hasVersionData_Test3() {
		assertFalse(new VersionRange().hasVersionData());
	}

	@Test
	public void getHumanView_Test1() {
		assertEquals(new VersionRange().getHumanReviewOutput("").toString(),
				"   vulnerable between  and  no fix found  ");
	}

	@Test
	public void findLast_Test1() {
		VersionRange vr = new VersionRange();
		Snippet name = new Snippet("Microsoft Internet Explorer");
		name.setLogicalUnit(new LogicalUnit("softwarename"));
		Snippet version = new Snippet("3.x");
		LogicalUnit lu = new LogicalUnit("version");
		lu.comment = "first detected vulnerability";
		version.setLogicalUnit(lu);
		NameVersionRelation nvr = new NameVersionRelation(name, version);
		vr.add(nvr);
		vr.findLast("cpe:/a:microsoft:ie:",
				Arrays.asList(new String[] { "cpe:/a:microsoft:ie:3.10.11", "cpe:/a:microsoft:ie:3.10.12:beta2" }),
				new ArrayList<String>());
		assertEquals("3.10.12:beta2", vr.lastDetectedVersion());
	}
}
