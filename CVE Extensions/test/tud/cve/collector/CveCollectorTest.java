package tud.cve.collector;

import static org.junit.Assert.*;

import java.io.File;

import org.junit.Test;

import tud.cve.extractor.Config;

public class CveCollectorTest {

	@Test
	public void splitCVExml_Test1() {
		Config.CVE_FOLDER="resource/test/";
		CveCollector.splitCVExml("resource/testFile2.xml");
		File file=new File("resource/test/CVE-2012-0001.xml");
		assertTrue(file.exists());
		file.delete();
	}

}
