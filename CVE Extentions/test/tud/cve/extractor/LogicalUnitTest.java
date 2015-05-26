package tud.cve.extractor;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

public class LogicalUnitTest {

	private LogicalUnit lu;
	
	@Before
	public void setUp(){
		lu=new LogicalUnit("version");
	}
	@Test
	public void isValidTypeTest() {
		assertTrue(lu.isValid());
	}

}
