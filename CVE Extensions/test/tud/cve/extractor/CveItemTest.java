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

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Before;
import org.junit.Test;

public class CveItemTest {

	CveItem cve;

	@Before
	public void setUp() {

		cve = new CveItem(AnalyseCves.getInnerText(new File("resource/testFile1.xml")));
	}

	@Test
	public void searchSnippetContext_Test1() throws Exception {
		cve.tokenList.get(0).next = cve.tokenList.get(1);
		cve.tokenList.get(1).prev = cve.tokenList.get(0);
		cve.tokenList.get(1).setLogicalUnit("version");
		cve.tokenList.get(0).setFeature("cuebegin", true);
		cve.searchSnippetcontext();
		assertEquals(cve.tokenList.get(1).logicalUnitComment(), "first detected vulnerability");
	}
	
	@Test
	public void searchSnippetContext_Test2() throws Exception {
		cve.tokenList.get(0).next = cve.tokenList.get(1);
		cve.tokenList.get(1).prev = cve.tokenList.get(0);
		cve.tokenList.get(1).setLogicalUnit("version");
		cve.tokenList.get(0).setFeature("cuebetween", true);
		cve.searchSnippetcontext();
		assertEquals(cve.tokenList.get(1).logicalUnitComment(), "first detected vulnerability");
	}
	
	@Test
	public void searchSnippetContext_Test3() throws Exception {
		cve.tokenList.get(0).next = cve.tokenList.get(1);
		cve.tokenList.get(0).setFeature("cueearlier", true);
		cve.tokenList.get(1).prev = cve.tokenList.get(0);
		cve.tokenList.get(1).setLogicalUnit("version");
		cve.tokenList.get(1).setFeature("comparingword", true);
		cve.tokenList.get(1).next=cve.tokenList.get(2);
		cve.tokenList.get(2).prev=cve.tokenList.get(1);
		cve.tokenList.get(2).setLogicalUnit("version");
		cve.searchSnippetcontext();
		assertEquals(cve.tokenList.get(2).logicalUnitComment(), "last detected vulnerability");
	}
	
	@Test
	public void searchSnippetContext_Test4() throws Exception {
		cve.tokenList.get(0).next = cve.tokenList.get(1);
		cve.tokenList.get(0).setFeature("cuebegin", true);
		cve.tokenList.get(1).prev = cve.tokenList.get(0);
		cve.tokenList.get(1).setLogicalUnit("version");
		cve.tokenList.get(1).setFeature("comparingword", true);
		cve.tokenList.get(1).next=cve.tokenList.get(2);
		cve.tokenList.get(2).prev=cve.tokenList.get(1);
		cve.tokenList.get(2).setLogicalUnit("version");
		cve.searchSnippetcontext();
		assertEquals(cve.tokenList.get(2).logicalUnitComment(), "first detected vulnerability");
	}
	
	@Test
	public void searchSnippetContext_Test5() throws Exception {
		cve.tokenList.get(0).next = cve.tokenList.get(1);
		cve.tokenList.get(1).prev = cve.tokenList.get(0);
		cve.tokenList.get(1).setLogicalUnit("version");
		cve.tokenList.get(0).setFeature("cuebetween", true);
		cve.tokenList.get(1).next=cve.tokenList.get(2);
		cve.tokenList.get(2).prev=cve.tokenList.get(1);
		cve.tokenList.get(2).setLogicalUnit("version");
		cve.searchSnippetcontext();
		assertEquals(cve.tokenList.get(2).logicalUnitComment(), "last detected vulnerability");
	}
	
	@Test
	public void getSnippetsWithLogicalUnits_Test1(){
		cve.tokenList.get(0).setLogicalUnit("version");
		assertEquals(cve.tokenList.get(0),cve.getSnippetsWithLogicalUnits("version").get(0));
	}
}
