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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Test;

import tud.cve.extractor.LogicalUnit;

public class SnippetTest {

	Snippet softwareSnippet;
	Snippet versionSnippet;

	@Before
	public void setUp() {
		softwareSnippet = new Snippet("MacroMedia Flash Player");
		versionSnippet = new Snippet("3.1");
	}

	@Test
	public void logicalType_test1() {
		versionSnippet.initialize();
		assertTrue(versionSnippet.isLogicalType("version"));
	}

	@Test
	public void logicalType_test2() {
		versionSnippet.initialize();
		assertFalse(versionSnippet.isLogicalType("combat"));
	}

	@Test
	public void logicalEnd_test1() {
		versionSnippet = new Snippet("3.1,");
		versionSnippet.initialize();
		assertTrue(versionSnippet.islogicalEnd());
	}

	@Test
	public void logicalEnd_test2() {
		versionSnippet = new Snippet("3.1.");
		versionSnippet.initialize();
		assertTrue(versionSnippet.islogicalEnd());
	}

	@Test
	public void logicalEnd_test3() {
		versionSnippet = new Snippet("");
		versionSnippet.initialize();
		assertTrue(versionSnippet.islogicalEnd());
	}

	@Test
	public void logicalStart_test1() {
		versionSnippet = new Snippet("");
		versionSnippet.initialize();
		assertTrue(versionSnippet.islogicalStart());
	}

	@Test
	public void logicalStart_test2() {
		versionSnippet = new Snippet("");
		versionSnippet.prev = new Snippet("");
		versionSnippet.prev.initialize();
		versionSnippet.initialize();
		assertTrue(versionSnippet.islogicalStart());
	}

	@Test
	public void mergeWithNextSnippet_Test1() {
		versionSnippet.next = new Snippet("update 10");
		versionSnippet.next.initialize();
		versionSnippet.initialize();
		versionSnippet.mergeWithNextSnippet();
		assertNull(versionSnippet.next);
	}

	@Test
	public void mergeWithNextSnippet_Test2() {
		versionSnippet.next = new Snippet("update 10");
		versionSnippet.next.initialize();
		versionSnippet.initialize();
		versionSnippet.mergeWithNextSnippet();
		assertEquals(versionSnippet.getTokenValue(), 2);
	}

	@Test
	public void mergeWithNextSnippet_Test3() {
		versionSnippet.next = new Snippet("update 10");
		versionSnippet.next.next = new Snippet("build 77");
		versionSnippet.next.next.initialize();
		versionSnippet.next.initialize();
		versionSnippet.initialize();
		versionSnippet.mergeWithNextSnippet();
		versionSnippet.mergeWithNextSnippet();
		assertEquals(versionSnippet.getTokenValue(), 3);
	}

	@Test
	public void mergeWithNextSnippet_Test4() {
		versionSnippet.next = new Snippet("update 10");
		versionSnippet.next.next = new Snippet("build 77");
		versionSnippet.next.next.initialize();
		versionSnippet.next.initialize();
		versionSnippet.initialize();
		versionSnippet.mergeWithNextSnippet();
		versionSnippet.mergeWithNextSnippet();
		assertEquals(versionSnippet.getText(), "3.1 update 10 build 77");
	}

	@Test
	public void combinitionLen_Test1() {
		versionSnippet.next = new Snippet("update 10");
		versionSnippet.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.next = new Snippet("build 77");
		versionSnippet.next.next.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.next.initialize();
		versionSnippet.next.initialize();
		versionSnippet.initialize();
		assertEquals(versionSnippet.combinationLen(), 1);
	}

	@Test
	public void combine_Test1() {
		versionSnippet.next = new Snippet("update 10");
		versionSnippet.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.next = new Snippet("build 77");
		versionSnippet.next.next.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.next.initialize();
		versionSnippet.next.initialize();
		versionSnippet.initialize();
		versionSnippet.combine();
		assertEquals(versionSnippet.combinationLen(), 0);
	}

	@Test
	public void combine_Test2() {
		versionSnippet.next = new Snippet("update 10");
		versionSnippet.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.setLogicalUnit(new LogicalUnit("version"));
		Snippet b77 = new Snippet("build 77");
		versionSnippet.next.next = b77;
		versionSnippet.next.next.setLogicalUnit(new LogicalUnit("version"));
		versionSnippet.next.next.initialize();
		versionSnippet.next.initialize();
		versionSnippet.initialize();
		versionSnippet.combine();
		assertEquals(versionSnippet.next, b77);
	}

	@Test
	public void condition_Test1() throws Exception {
		assertFalse(versionSnippet.condition(""));
	}

	@Test(expected = Exception.class)
	public void condition_Test2() throws Exception {
		assertFalse(versionSnippet.condition("!cuebegin"));
	}

	@Test(expected = Exception.class)
	public void condition_Test3() throws Exception {
		assertFalse(versionSnippet.condition("-cuebegin"));
	}

	@Test
	public void condition_Test4() throws Exception {
		versionSnippet.setText("before");
		versionSnippet.initialize();
		assertFalse(versionSnippet.condition("-cuebefore"));
	}

	@Test
	public void condition_Test5() throws Exception {
		versionSnippet.setText("earlier");
		versionSnippet.initialize();
		assertFalse(versionSnippet.condition("!cuebefore"));
	}

	@Test
	public void condition_Test6() throws Exception {
		versionSnippet.setText("earlier");
		versionSnippet.initialize();
		assertFalse(versionSnippet.condition("/cuebefore/comma"));
	}

	@Test
	public void condition_Test7() throws Exception {
		versionSnippet.setText("before");
		versionSnippet.initialize();
		assertTrue(versionSnippet.condition("/cuebefore/comma"));
	}

}
