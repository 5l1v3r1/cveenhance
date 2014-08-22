package CveCollector;

/**
 * This class should represent a part of a floating text
 * @author TU Darmstadt KOM, TU Darmstadt STG
 * @version 0.1
 */
public class Snippet {

	protected static int number; 	// start of text subset
	protected static String text; 	// floating text part
	
	public Snippet(String innerText, int nummer) {
		number=nummer;
		text=innerText;
	}
	
	/**
	 * @return the start of the floating text subset
	 */
	public int getStart(){
		return number;
	}
	
	/**
	 * @return the part of the floating text
	 */
	public String getText(){
		return text;
	}
	
	/**
	 * @return the end of the floating text subset
	 */
	public void setText(String newText){
		text=newText;
	}
	
	/**
	 * toString method for simple output in messages 
	 */
	public String toString(){
		return getText();
	}
	
}
