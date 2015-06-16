package tud.cve.data.representation;

/*
 * This work is licensed under the MIT License. 
 * The MIT License (MIT)

 * Copyright (c) 2015  Leonid Glanz (STG), Sebastian Schmidt (KOM), Sebastian Wollny (KOM), 
 * Ben Hermann (STG), Technische Universit�t Darmstadt

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

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class NVRTest {

	private Snippet smallVersion = new Snippet("3.1");
	private Snippet smallVersion1 = new Snippet("3.1.0");
	private Snippet midVersion = new Snippet("3.2");
	private Snippet midVersionZero = new Snippet("3.2.0");
	private Snippet midVersionCross = new Snippet("3.2.x");
	private Snippet midLongVersion = new Snippet("3.2.1");
	private Snippet midCountVersionSnippetSmall = new Snippet("3.2.9");
	private Snippet midCountVersionSnippetBig = new Snippet("3.2.10");
	private Snippet shortMidVersionSnippet = new Snippet("4");
	private Snippet shortBigVersionSnippet = new Snippet("5");
	private Snippet multiTokenVersionSnippet1 = new Snippet("3.2 update 3");
	private Snippet multiTokenVersionSnippet2 = new Snippet("3.2 update 4");
	private Snippet multiTokenVersionSnippet3 = new Snippet("3.2 rt 3");

	private Snippet softwareNameSnippet1 = new Snippet("Macromedia Flash");
	private Snippet softwareNameSnippet2 = new Snippet("Mozilla Firefox");

	private NameVersionRelation nvrSmallVersion = new NameVersionRelation(softwareNameSnippet1, smallVersion);
	private NameVersionRelation nvrMidVersion = new NameVersionRelation(softwareNameSnippet1, midVersion);

	private NameVersionRelation nvr;

	@Before
	public void setUp() {
		nvr = new NameVersionRelation(new Snippet("Macromedia Flash"), new Snippet("3.1"));
		nvr.version().initialize();
		nvr.name().initialize();
	}

	@Test
	public void optimizeVersionTest() {
		nvr.setVersion(new Snippet("3.x"));
		assertEquals(nvr.optimizeVersion(nvr.version().getText()), "3");
	}

	@Test
	public void optimizeVersionTest1() {
		nvr.setVersion(new Snippet("3.0"));
		assertEquals(nvr.optimizeVersion(nvr.version().getText()), "3");
	}

	@Test
	public void toStringTest() {
		assertTrue(nvr.toString().equals(nvr.name() + " " + nvr.version()));
	}

	@Test
	public void trimmedVersion_Test1() {
		assertEquals(nvr.trimVersion(" 3  "), "3");
	}

	@Test
	public void trimmedVersion_Test2() {
		assertEquals(nvr.trimVersion(" 3 1 "), "3");
	}

	@Test
	public void trimmedVersion_Test3() {
		assertEquals(nvr.trimVersion(" 3.x "), "3");
	}

	@Test
	public void trimmedVersion_Test4() {
		assertEquals(nvr.trimVersion(" 3.0 "), "3");
	}

	@Test
	public void trimmedVersion_Test5() {
		assertEquals(nvr.trimVersion(" 3.0.0 "), "3.0");
	}

	@Test
	public void hasSameSuperversion_Test1() {
		assertTrue(nvr.hasSameSuperversion(new NameVersionRelation(softwareNameSnippet1, midVersion)));
	}

	@Test
	public void hasSameSuperversion_Test2() {
		nvr.setVersion(midCountVersionSnippetSmall);
		assertTrue(nvr.hasSameSuperversion(new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet1)));
	}

	@Test
	public void hasSameSuperversion_Test3() {
		nvr.setVersion(smallVersion);
		assertTrue(nvr.hasSameSuperversion(new NameVersionRelation(softwareNameSnippet1, midVersionZero)));
	}

	@Test
	public void hasSameSuperversion_Test4() {
		nvr.setVersion(smallVersion1);
		assertFalse(nvr.hasSameSuperversion(new NameVersionRelation(softwareNameSnippet1, midVersionZero)));
	}

	@Test
	public void crossCheckTest() {
		assertTrue(leftIsSmaller(nvrSmallVersion, nvrMidVersion));
		assertTrue(leftIsBigger(nvrMidVersion, nvrSmallVersion));
		NameVersionRelation left = new NameVersionRelation(softwareNameSnippet1, midVersionZero);
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midLongVersion);
		assertTrue(leftIsSmaller(left, right));
		assertTrue(leftIsBigger(right, left));
		left = new NameVersionRelation(softwareNameSnippet1, midCountVersionSnippetSmall);
		right = new NameVersionRelation(softwareNameSnippet1, midCountVersionSnippetBig);
		assertTrue(leftIsSmaller(left, right));
		assertTrue(leftIsBigger(right, left));
		left = new NameVersionRelation(softwareNameSnippet1, shortMidVersionSnippet);
		right = new NameVersionRelation(softwareNameSnippet1, shortBigVersionSnippet);
		assertTrue(leftIsSmaller(left, right));
		assertTrue(leftIsBigger(right, left));
	}

	@Test
	public void equalTest() {
		assertTrue(leftIsEqual(nvrSmallVersion, nvrSmallVersion));
	}

	@Test
	public void equalTestZeros() {
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midVersionZero);
		assertTrue(leftIsEqual(nvrMidVersion, right));
	}

	@Test
	public void equalTestCrosses() {
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midVersionCross);
		assertTrue(leftIsEqual(nvrMidVersion, right));
	}

	@Test
	public void differentTreeDepthTest1() {
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midLongVersion);
		assertTrue(leftIsSmaller(nvrMidVersion, right));
	}

	@Test
	public void differentTreeDepthTest2() {
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midCountVersionSnippetBig);
		assertTrue(leftIsSmaller(nvrSmallVersion, right));
	}

	@Test
	public void differentTreeDepthTestWithExtention() {
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet1);
		assertTrue(leftIsSmaller(nvrSmallVersion, right));
		assertTrue(leftIsSmaller(nvrMidVersion, right));
		NameVersionRelation left = new NameVersionRelation(softwareNameSnippet1, midVersionZero);
		assertTrue(leftIsSmaller(left, right));
		left = new NameVersionRelation(softwareNameSnippet1, midVersionCross);
		assertTrue(leftIsSmaller(left, right));
	}

	@Test
	public void TestWithExtention() {
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet2);
		NameVersionRelation left = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet1);
		assertTrue(leftIsSmaller(left, right));
	}

	@Test
	public void TestWithDifferentExtention() {
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet3);
		NameVersionRelation left = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet2);
		assertTrue(leftIsBigger(left, right));
	}

	// ------ end of test cases -----

	boolean leftIsSmaller(NameVersionRelation left, NameVersionRelation right) {
		if (left.compareTo(right) < 0)
			return true;
		else if (left.compareTo(right) == 0)
			return false;
		else
			return false;
	}

	boolean leftIsEqual(NameVersionRelation left, NameVersionRelation right) {
		if (left.compareTo(right) == 0)
			return true;
		else
			return false;
	}

	boolean leftIsBigger(NameVersionRelation left, NameVersionRelation right) {
		if (left.compareTo(right) > 0)
			return true;
		else if (left.compareTo(right) == 0)
			return false;
		else
			return false;
	}

}
