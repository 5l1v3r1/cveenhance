package CveCollector;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

public class VersionRange{
	
	String firstDetectedVersion="";
	String lastDetectedVersion="";
	String fixedVersion="";
	String softwareName="";
	String generalCpeString="";
	Snippet fixedSoftware;
	boolean empty;
	private boolean fixed;
	
	private ArrayList<NameVersionRelation> versions;
	
	public ArrayList<NameVersionRelation> versionList(){
		return versions;
	}
	
	public VersionRange(){
		empty=true;
		versions=new ArrayList<NameVersionRelation>();
		fixed=false;
	}
	
	public NameVersionRelation shortest(){
		return versions.get(0); // TODO: Check if get method starts with 0 !!!!
	}
	
	public NameVersionRelation biggest(){
		return versions.get(versions.size()-1);
	}
	
	private void isFixed(){
		if(!fixed){
			Iterator<NameVersionRelation> nvrIt = versions.iterator();
			Snippet version;
			while(nvrIt.hasNext()){
				version=nvrIt.next().version();
				if(version.logicalUnitComment().equals("fixed")) {
					fixed=true;
					fixedSoftware=version;
					break;
					}
				else if(!nvrIt.hasNext())fixed=false;
			}
		}
	}
	
	public boolean fixed(){
		return fixed;
	}
	
	public Snippet fixedSoftware(){
		return fixedSoftware;
	}
	
	public void add(NameVersionRelation nvr){
		if(empty){
			softwareName=nvr.name().getText();
			empty=false;
		}
		versions.add(nvr);
		Collections.sort(versions);
		isFixed();
	}
	
	public void addAll(Collection<NameVersionRelation> c){
		if(c.size()>0){
			if(empty){
				softwareName=c.iterator().next().name().getText();
				empty=false;
			}
			versions.addAll(c);
			Collections.sort(versions);
			isFixed();
		}	
	}
	
	public String toString(){
		String returnStr = softwareName+" vulnerable between "+shortest().version().getText()+" and "+biggest().version().getText();
		if(fixed) returnStr+=" fix:"+fixedSoftware().getText();
		else returnStr+= " no fix found";
		return returnStr;
		
	}


}
