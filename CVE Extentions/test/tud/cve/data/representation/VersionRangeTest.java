package tud.cve.data.representation;

import static org.junit.Assert.*;

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
	public void hasVersionData_Test1(){
		assertTrue(last.hasVersionData());
	}
	
	@Test
	public void hasVersionData_Test2(){
		assertTrue(fix.hasVersionData());
	}
	
	@Test
	public void hasVersionData_Test3(){
		assertFalse(new VersionRange().hasVersionData());
	}
	
	@Test
	public void getHumanView_Test1(){
		assertEquals(new VersionRange().getHumanReviewOutput("").toString(),"   vulnerable between  and  no fix found  ");
	}
}
