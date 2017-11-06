/**
 * @author Solomon Sonya
 */


package Driver;

import java.io.File;

import javax.swing.JFileChooser;

import Sockets.*;
import whois.Whois_Driver;

public class Start extends Thread implements Runnable
{
	public static final String myClassName = "Start";
	public static volatile Driver driver = new Driver();
	public static volatile StandardInListener std_in = new StandardInListener();
	
	//cache TLD's
	Whois_Driver whois_driver = new Whois_Driver(Whois_Driver.arrCommon_TLDs, Whois_Driver.EXECUTION_ACTION_CACHE_MOST_COMMON_TLDS);
	
	public Start(String args [])
	{
		try
		{
			analyze_input(args);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	
	public boolean analyze_input(String [] args)
	{
		try
		{						
			if(args.length > 0)
			{
				
				if(args[0].toLowerCase().trim().contains("import"))
				{
					File fle = driver.querySelectFile(true, "Please specify list of Domain Names to derive...", JFileChooser.FILES_ONLY, false, false);
					
					if(fle == null || !fle.exists())
					{
						driver.directive("* * * ERROR! NO FILE SELECTED!!!");
						return false;
					}
					
					Whois_Driver whois_driver = new Whois_Driver(fle, Whois_Driver.EXECUTION_ACTION_DERIVE_WHOIS_REGISTRATION_INFO_FROM_DOMAIN_NAME_LIST);
					
				}
				
				else//perhaps a file path was already specified
				{
					String file_path = args[0].trim();
					
					File fle = new File(file_path);
					
					if(fle != null && fle.isFile() && fle.exists())
					{
						Whois_Driver whois_driver = new Whois_Driver(fle, Whois_Driver.EXECUTION_ACTION_DERIVE_WHOIS_REGISTRATION_INFO_FROM_DOMAIN_NAME_LIST);
					}
				}
				
				
			}
			
			return true;
		}
		catch(Exception e)
		{
			//driver.eop(myClassName, "analyze_input", e);
			driver.directive("NOTE: Input received does not match expected file of domains for me to retrieve...");
		}
		
		return false;
	}
}
