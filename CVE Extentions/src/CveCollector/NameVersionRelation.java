package CveCollector;

public class NameVersionRelation implements Comparable<NameVersionRelation>{
	private Snippet name;
	private Snippet version;
	private String cpe;

	
	public NameVersionRelation(Snippet softwareName, Snippet softwareVersion) {
		name=softwareName;
		version=softwareVersion;
		cpe="";
	} 
	
	public Snippet name(){
		return name;
	}
	
	public Snippet version(){
		return version;
	}
	
	public void setName(Snippet newName){
		name=newName;
	}
	
	public void setVersion(Snippet newVersion){
		version=newVersion;
	}
	
	public void setCPE(String newCPE){
		cpe=newCPE;
	}
	
	public String cpe(){
		return cpe;
	}
	
	public String toString(){
		String versioninfo="";
		if(!version.logicalUnitComment().equals("")) versioninfo=" ("+version.logicalUnitComment()+")";
		return name+" "+version+versioninfo;
	}
	
	public String trimmedVersion(){
		return trimVersion(version.getText());
	}
	
	private String trimVersion(String version){
		if(version.contains(" "))version=version.substring(0, version.indexOf(" "));
		version=version.trim();
		if(version.length()>1 && version.substring(version.length()-2).equals(".x"))version=version.substring(0, version.length()-2);
		else if(version.length()>1 && version.substring(version.length()-2).equals(".0"))version=version.substring(0, version.length()-2);
		return version;
	}
	
	public boolean refersSameSoftware(NameVersionRelation otherRel){
		return name().getText().equalsIgnoreCase(otherRel.name().getText());
	}
	
	public boolean versionIsMoreGeneral(NameVersionRelation otherRel){
		if(otherRel.version().getText().contains(trimmedVersion())) return true;
		return false;
	}
	
	public boolean hasSameSuperversion(NameVersionRelation otherRel) {
		String otherVersion = otherRel.version().getText();
		String[] splittedVersion=version.getText().split("\\.");
		String[] splittedOtherVersion=otherVersion.split("\\.");
		if(splittedVersion.length<2 || splittedOtherVersion.length<2) {
			if(splittedVersion[0]==splittedOtherVersion[0]) return true;
			return false;
		}
		else{
			for(int i=0;(i<(splittedVersion.length-1))&&(i<splittedOtherVersion.length-1);i++){
				if(splittedVersion[i]!=splittedOtherVersion[i]) return false;
			}
			return true;
		}
	}
	
	public boolean equals (NameVersionRelation otherRelation){
		return this.hashCode()==otherRelation.hashCode();
	}
	@Override
	public int hashCode (){
		return (name.getText()+trimmedVersion()).hashCode();
	}

	@Override
	public int compareTo(NameVersionRelation otherNVR) {
	    if (otherNVR.trimmedVersion() == null && this.trimmedVersion() == null) {
	        return 0;
	      }
	      if (this.trimmedVersion() == null) {
	        return 1;
	      }
	      if (otherNVR.trimmedVersion() == null) {
	        return -1;
	      }
	      String[] versionSplit = this.trimmedVersion().split("\\.");
	      String[] otherVersionSplit =otherNVR.trimmedVersion().split("\\.");
	      if(versionSplit.length>1&&otherVersionSplit.length>1){
	    	  try{ // Try to convert versionnumber into Integer and compare it
	    		  for(int i=0;i<versionSplit.length;i++){
	    			  if(i>=otherVersionSplit.length) return 1;
	    			  if(Integer.parseInt(versionSplit[i])>Integer.parseInt(otherVersionSplit[i])) return 1;
	    			  if(Integer.parseInt(versionSplit[i])<Integer.parseInt(otherVersionSplit[i])) return -1;
	    		  }
	    		  if(otherVersionSplit.length>versionSplit.length) return -1;
	    	  }
	    	  catch(Exception e){
	    		  
	    	  }
	      }
	      CharSequence version = this.trimmedVersion();
	      CharSequence otherVersion = otherNVR.trimmedVersion();
	      Character versionCharater;
	      Character otherVersionCharacter;
	      for (int i = 0; i<version.length() && i<otherVersion.length() ; i++){ // character-wise compare
	    	  versionCharater=new Character(version.charAt(i));
	    	  otherVersionCharacter= new Character(otherVersion.charAt(i));
	    	  if(versionCharater.compareTo(otherVersionCharacter)!=0) return versionCharater.compareTo(otherVersionCharacter);
	      }
	      if(version.length()==otherVersion.length()) return 0;
	      if(version.length()<otherVersion.length()) return -1;
	      else return 1;
	}


	
	
}
