package tud.cve.extractor;

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
