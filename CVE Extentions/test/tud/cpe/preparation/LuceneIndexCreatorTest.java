package tud.cpe.preparation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.File;
import java.io.IOException;

import org.apache.lucene.queryparser.classic.ParseException;
import org.junit.Test;

public class LuceneIndexCreatorTest {

	@Test
	public void cpeDecoding_Test1() {
		assertEquals(LuceneIndexCreator.cpeDecoding(""), "");
	}

	@Test
	public void cpeDecoding_Test2() {
		assertEquals(LuceneIndexCreator.cpeDecoding("cpe:/a:ibm:java:1.6.0:update_10"),
				"cpe a ibm java 1.6.0 update_10");
	}

	@Test
	public void cpeDecoding_Test3() {
		assertEquals(LuceneIndexCreator.cpeDecoding(null), "");
	}

	@Test
	public void transformTitle_Test1() {
		assertEquals(LuceneIndexCreator.transformTitle(""), "");
	}

	@Test
	public void transformTitle_Test2() {
		assertEquals(LuceneIndexCreator.transformTitle(null), "");
	}

	@Test
	public void transformTitle_Test3() {
		assertEquals(LuceneIndexCreator.transformTitle("Oracle Java Runtime Environment 1.6.0 Update 55"),
				"Oracle Java Runtime Environment 1 6 0 Update 55");
	}

	@Test
	public void findTitle_Test1() {
		LuceneIndexCreator.index_file=new File("./data/index");
		
		try {
			assertEquals(LuceneIndexCreator.findTitle("cpe:/a:oracle:jre:1.6.0:update_55"),
					"Oracle Java Runtime Environment 1 6 0 Update 55");
		} catch (IOException e) {
			fail(e.getMessage());
		} catch (ParseException e) {
			fail(e.getMessage());
		}
	}

}
