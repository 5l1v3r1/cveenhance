package CveCollector;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Section {
	
	private ArrayList<Snippet> Snippets = new ArrayList<Snippet>(); 

	public Section() {
	}
	
	private Section next = null;
	
	private Section prev = null;
	
	public void setNextSection(Section newNextSection){
		next=newNextSection;
	}
	
	public void setPrevSection(Section newPrevSection){
		prev=newPrevSection;
	}
//	
//	public Snippet searchForSnippet(String commandString){
//		Iterator<Snippet> snipIt = Snippets.iterator();	
//		Snippet currentTestSnip;
//		try {
//			while(snipIt.hasNext())	{
//					currentTestSnip=snipIt.next();
//					if (checkSnippetAttributes(currentTestSnip, commandString)) return currentTestSnip;
//				}
//		} catch (Exception e) {
//				e.printStackTrace();
//			return null;
//		}
//		
//		
//		return null;
//	}
//	
//	private boolean checkSnippetAttributes(Snippet checkSnip, String checkCondition) throws Exception{
//		// check Snippet condition for variable; e.g. possibleVersion = true -> "$possibleVersion:true;"
//		
//		Matcher matcher_VarName = Pattern.compile("$\\w*:").matcher(checkCondition);
//		Matcher matcher_Value = Pattern.compile(":.*;").matcher(checkCondition);
//		boolean cond1=matcher_VarName.find();
//		boolean cond2=matcher_Value.find();
//		while(cond1 || cond2){
//			if (cond1==false || cond2==false) throw new Exception("Check String not processable! Number of valid vars does not match with number of vals ");
//			String var=matcher_VarName.group();
//			String val=matcher_Value.group();
//			
//			
//			cond1=matcher_VarName.find();
//			cond2=matcher_Value.find();
//		}
//		
//		return false;
//	}
//	
	public void addSnippet(Snippet newSnip){
		Snippets.add(newSnip);
	}
	
	public ArrayList<Snippet> getSnippets(){
		return Snippets;
	}

}
