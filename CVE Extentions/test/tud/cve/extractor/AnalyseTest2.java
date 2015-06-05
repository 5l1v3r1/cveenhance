package tud.cve.extractor;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class AnalyseTest2 {
	
	AnalyseCves ac;
	
	@Before
	public void setUp(){
		ac=new AnalyseCves();
	}

	@Test
	public void convertCpeToText_Test1() {
		assertEquals(ac.convertCpeToText("cpe:/a:ibm:java:1.7.0:update_55:windows"),"ibm java");
	}

}
