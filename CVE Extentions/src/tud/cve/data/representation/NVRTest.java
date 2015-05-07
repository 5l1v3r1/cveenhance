package tud.cve.data.representation;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import tud.cve.extractor.CveItem;

public class NVRTest {
	
	private Snippet smallVersion = new Snippet("3.1");
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
	private NameVersionRelation nvrMidVersion= new NameVersionRelation(softwareNameSnippet1, midVersion);
	
	
	@Test
	public void crossCheckTest(){
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
	public void equalTest(){
		assertTrue(leftIsEqual(nvrSmallVersion, nvrSmallVersion));
	}
	
	@Test
	public void equalTestZeros(){
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midVersionZero);
		assertTrue(leftIsEqual(nvrMidVersion, right));
	}
	
	@Test
	public void equalTestCrosses(){
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midVersionCross);
		assertTrue(leftIsEqual(nvrMidVersion, right));
	}
	
	@Test
	public void differentTreeDepthTest1(){
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midLongVersion);
		assertTrue(leftIsSmaller(nvrMidVersion, right));
	}
	
	@Test
	public void differentTreeDepthTest2(){
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, midCountVersionSnippetBig);
		assertTrue(leftIsSmaller(nvrSmallVersion, right));
	}
	
	@Test
	public void differentTreeDepthTestWithExtention(){
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet1);
		assertTrue(leftIsSmaller(nvrSmallVersion, right));
		assertTrue(leftIsSmaller(nvrMidVersion, right));
		NameVersionRelation left = new NameVersionRelation(softwareNameSnippet1, midVersionZero);
		assertTrue(leftIsSmaller(left, right));
		left = new NameVersionRelation(softwareNameSnippet1, midVersionCross);
		assertTrue(leftIsSmaller(left, right));
	}
	
	@Test
	public void TestWithExtention(){
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet2);
		NameVersionRelation left = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet1);
		assertTrue(leftIsSmaller(left, right));
	}
	
	@Test
	public void TestWithDifferentExtention(){
		NameVersionRelation right = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet3);
		NameVersionRelation left = new NameVersionRelation(softwareNameSnippet1, multiTokenVersionSnippet2);
		assertTrue(leftIsBigger(left, right));
	}
	
	
	
	boolean leftIsSmaller(NameVersionRelation left, NameVersionRelation right){
		if(left.compareTo(right)<0) return true;
		else if(left.compareTo(right)==0) return false;
		else return false;
	}
	
	boolean leftIsEqual(NameVersionRelation left, NameVersionRelation right){
		if(left.compareTo(right)==0) return true;
		else return false;
	}
	
	boolean leftIsBigger(NameVersionRelation left, NameVersionRelation right){
		if(left.compareTo(right)>0) return true;
		else if(left.compareTo(right)==0) return false;
		else return false;
	}
	

}

