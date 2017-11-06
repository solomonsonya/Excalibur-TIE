/**
 * @author Solomon Sonya
 */


package Sockets;

import Driver.Driver;
import Node.Node_GeoIP;
import Node.Node_Nslookup;
import whois.*;

import java.io.*;

import javax.swing.JFileChooser;


public class StandardInListener extends Thread implements Runnable
{
	public static volatile Driver driver = new Driver();
	public static final String myClassName = "StandardInListener";
	public static volatile boolean continue_run = true;
	
	public static String [] arr = null;
	
	public volatile String lower = "";
	
	public static final String import_file = "import";
	public static final String TLD = "tld";
	public static final String DERIVE_TLD_REGISTRARS1 = "derive tld registrar", DERIVE_TLD_REGISTRARS2 = "derive_tld_registrar";
	public static final String STORE_TLD_REGISTRARS1 = "store tld registrar", STORE_TLD_REGISTRARS2 = "store_tld_registrar";
	public static final String REGISTRAR = "registrar";
	public static final String debug = "debug";
	public static final String whois = "whois";
	public static final String import_whois_list = "import_whois_list", import_whois_list2 = "import whois list";
	public static final String update_geo = "update_geo", update_geo2 = "update geo";
	public static final String geo = "geo";
	public static final String nslookup = "nslookup";
	public static final String map_whois1 = "map";
	public static final String ingest_excalibur_whois_directory = "ingest_excalibur_whois_directory", ingest_excalibur_whois_directory2 = "ingest excalibur whois directory";
	public static final String import_excalibur_whois_data_file = "import_excalibur_whois_data_file", import_excalibur_whois_data_file2 = "import excalibur whois data file";
	
	
	public static final String [] arrHelp = 
		{
				"\n//////////////////  HELP  ///////////////////",
				"h\t\t- Display Help",
				import_file + "\t\t- Import file to be injested",
				TLD + "\t\t- Determine registrar for TLD e.g. COM, ORG, NET, etc",
				REGISTRAR + "\t- Determine registrar whois for a particular domain name e.g. google.com",
				whois + "\t\t- Perform whois lookup on a specified domain name",
				DERIVE_TLD_REGISTRARS1 + "- Import list to derive TLD registrars",
				STORE_TLD_REGISTRARS1 + "- Store tsv list of TLD registrars",
				import_whois_list + " - Import file of domain names to derive whois registration informaiton",
				update_geo + "\t- Invoke action to update whois nodes without a valid geo location",
				geo + "\t\t- Perform GEO lookup on a specified domain name",
				nslookup + "\t- Perform nslookup lookup on a specified domain name",
				map_whois1 + "\t\t- Perform whois retrieval and map results in html webpage",
				ingest_excalibur_whois_directory + "- Specify directory populated with whois files per domain to import each file for analysis",
				import_excalibur_whois_data_file + "- Import single (normalized) Excalibur whois data file",
				
				debug + "\t\t- Toggle debug for whois messages on or off",
		};
	
	public StandardInListener()
	{
		try
		{
			this.start();
			
			
		}
		catch(Exception e)
		{
			
		}
	}
	
	public void run()
	{
		try
		{
			driver.directive("WELCOME to " + driver.FULL_NAME + " by Solomon Sonya @Carpenter1010");
			
			displayHelp();
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(System.in));
			String line = "";
			
			while((line = brIn.readLine()) != null && continue_run)
			{
				line = line.trim();
				lower = line.toLowerCase().trim();
				
				if(line.equals(""))
					continue;

				if(lower.equals("h") || lower.equals("help") || line.equals("-h") || line.equals("-help"))
					displayHelp();
				
				else if(lower.startsWith(TLD))
					determine_tld_registrar(line);
				
				else if(lower.startsWith(DERIVE_TLD_REGISTRARS1) || lower.startsWith(DERIVE_TLD_REGISTRARS2))
					determine_tld_registrar_list();
				
				else if(lower.startsWith(STORE_TLD_REGISTRARS1) || lower.startsWith(STORE_TLD_REGISTRARS2))
					store_tld_registrar_list();
				
				else if(lower.startsWith(REGISTRAR))
					determine_registrar(line);
				
				else if(lower.equals(debug))
					toggle_debug();
				
				else if(lower.startsWith(whois))
					whois(line);
				
				else if(lower.startsWith(import_whois_list) || lower.startsWith(import_whois_list2))
					derive_whois_list(line);
				
				else if(lower.startsWith(update_geo) || lower.startsWith(update_geo2))
					update_geo();
				
				else if(lower.startsWith(geo))
					geo(line);
				
				else if(lower.startsWith(nslookup))
					nslookup(line);
				
				else if(lower.startsWith(map_whois1))
					map_whois(line);
				
				else if(lower.startsWith(ingest_excalibur_whois_directory) || lower.startsWith(ingest_excalibur_whois_directory2))
					ingest_excalibur_whois_directory(line);
				
				else if(lower.startsWith(import_excalibur_whois_data_file) || lower.startsWith(import_excalibur_whois_data_file2))
					this.import_excalibur_whois_data_file(line);
				
				else
					driver.directive("Unknown command received. Run help if necessary...");
				
			}
			
			driver.directive("\n\nPUNT! Out of infinite while in " + myClassName);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean ingest_excalibur_whois_directory(String line)
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please specify directory of whois files to ingest...", JFileChooser.DIRECTORIES_ONLY, false, false);
			
			if(fle == null)
			{
				driver.directive("Action canceled!");
				return false;
			}
			if(fle != null && fle.exists() && fle.isDirectory())
			{
				Whois_Driver whois = new Whois_Driver(fle, Whois_Driver.EXECUTION_ACTION_INGEST_DIRECTORY_OF_WHOIS_FILES);
			}
			else
				driver.directive("Invalid file specified!");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ingest_excalibur_whois_directory", e);
		}
		
		return false;
	}
	
	public boolean map_whois(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
			{
				driver.directive("PUNT! Invalid information. Domain name is missing in map whois request...");
				return false;
			}

			//normalize
			line = line.substring(3).trim();
			
			if(line.trim().equals(""))
			{
				driver.directive("* * * PUNT! Invalid information. Domain name is missing in map whois request...");
				return false;
			}
			
			
			line = normalize_lookup(line);
			
			//determine if we have seen this before
			Whois whois = Whois.resolve(line);
									
			if(whois == null)
			{
				driver.directive("PUNT! Whois record does not exist for selected query [" + line + "]");
				return false;
			}
			
			driver.directive("\n");			
			whois.map_whois();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "map_whois", e);
		}
		
		return false;
	}
	
	public boolean import_excalibur_whois_data_file(String line)
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please specify Excalibur whois data file to import...", JFileChooser.FILES_ONLY, false, false);
			
			if(fle == null)
			{
				driver.directive("* Action canceled!!!");
				return false;
			}
			if(fle != null && fle.exists() && fle.isFile())
			{
				Whois_Driver whois = new Whois_Driver(fle, Whois_Driver.EXECUTION_ACTION_IMPORT_EXCALIBUR_WHOIS_DATA_FILE);
			}
			
			else
				driver.directive("Invalid file specified!");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_excalibur_whois_data_file", e);
		}
		
		return false;
	}
	
	public boolean geo(String line)
	{
		try
		{
			line = line.substring(3).trim();
			
			if(line.trim().equals(""))
			{
				driver.directive("PUNT! Invalid command.  Domain name is missing from your request");
				return false;
			}
			
			Node_GeoIP node = Node_GeoIP.resolve(line, false);
			
			if (node != null && node.parse_complete)
			{
				driver.directive(node.get_details(true, ": ", "\n"));
				driver.directive("");
			}
			else
				driver.directive("Punt! No data returned from selected query [" + line + "]");
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "geo", e);
		}
		
		return false;
	}
	
	public boolean nslookup(String line)
	{
		try
		{
			line = line.substring(8).trim();
			
			if(line.trim().equals(""))
			{
				driver.directive("PUNT!!! Invalid command.  Domain name is missing from your request");
				return false;
			}
			
			Node_Nslookup node = Node_Nslookup.resolve(line);
			
			if (node != null && node.parse_complete)
			{
				driver.directive(node.get_details(true, ": ", "\n"));
				driver.directive("");
			}
			else
				driver.directive("Punt!!! No data returned from selected query [" + line + "]");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "nslookup", e);
		}
		
		return false;
	}
	
	public boolean update_geo()
	{
		try
		{
			if(Node_GeoIP.geo_requests_per_hour_count > Node_GeoIP.max_geo_requests_per_hour)
			{
				driver.directive("PUNT! Unable to complete selected action.  Max lookups of [" + Node_GeoIP.max_geo_requests_per_hour + "] requests have been exceeded for this hour...");
				return false;
			}
			
			if(Whois.tree_whois_lookup.isEmpty())
			{
				driver.directive("PUNT! Whois list is currently empty!  Unable to continue until you populate with valid whois requests...");
				return false;
			}
			
			//otw... execute action
			Whois.update_geo();
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_geo", e);
		}
		
		return false;
	}
	
	public boolean derive_whois_list(String line)
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please specify list of Domain Names to derive...", JFileChooser.FILES_ONLY, false, false);
			
			if(fle == null || !fle.exists())
			{
				driver.directive("* * * ERROR! NO FILE SELECTED!!!");
				return false;
			}
			
			Whois_Driver whois_driver = new Whois_Driver(fle, Whois_Driver.EXECUTION_ACTION_DERIVE_WHOIS_REGISTRATION_INFO_FROM_DOMAIN_NAME_LIST);
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "derive_whois_list", e);
		}
		
		return false;
	}
	
	public boolean whois(String line)
	{
		try
		{
			line = line.substring(5).trim();
			
			if(line.startsWith(":"))
				line = line.substring(1).trim();
			
			if(Whois.tree_whois_lookup.containsKey(line.toLowerCase()))
				Whois.tree_whois_lookup.get(line.toLowerCase()).print_whois("\n");
			
			else
			{
				Whois whois = new Whois(line, Whois_Driver.EXECUTION_ACTION_PERFORM_WHOIS_LOOKUP);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "whois", e);
		}
		
		return false;
	}
	
	public boolean toggle_debug()
	{
		try
		{
			Whois.debug = !Whois.debug;
			
			if(Whois.debug)
				driver.directive("Whois debugging messages are ENABLED");
			else
				driver.directive("Whois debugging messages are DISABLED");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "toggle_debug", e);
		}
		
		return false;
	}
	
	public String determine_registrar(String line)
	{
		try
		{
			line = line.substring(9).toLowerCase().trim();
			
			if(line.trim().equals(""))
			{
				driver.directive("PUNT! Invalid format supplied. Domain name is missing from your request.");
				return null;
			}
			
			Whois_Driver whois = new Whois_Driver(line, Whois_Driver.EXECUTION_ACTION_DERIVE_REGISTRAR_WHOIS_SERVER);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determine_registrar", e);
		}
		
		return null;
	}
	
	public boolean determine_tld_registrar(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
			{
				driver.directive("INVALID INPUT FOR DETERMINE TLD REGISTRAR MTD");
				return false;
			}
			
			line = line.trim();
			
			//trim the instruction
			line = line.substring(3).trim();
			
			//validate
			if(line == null || line.trim().equals(""))
			{
				driver.directive("INVALID INPUT FOR DETERMINE TLD REGISTRAR MTD - You are missing lookup token after the command.");
				return false;
			}
			
			if(Whois.cache_IANA_TLD.containsKey(line))
			{
				driver.directive("TLD Registrar for [" + line + "] --> " + Whois.cache_IANA_TLD.get(line).TLD_WHOIS_REGISTRAR);
			}
			
			else
			{
				line = driver.normalize_domain_name(line);
				
				Whois_Driver whois_driver = new Whois_Driver(line, Whois_Driver.EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR);
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determine_tld_registrar", e);
		}
		
		return false;
	}
	
	
	
	
	public boolean determine_tld_registrar_list()
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please specify list of TLDs to derive...", JFileChooser.FILES_ONLY, false, false);
			
			if(fle == null || !fle.exists())
			{
				driver.directive("ERROR! NO FILE SELECTED!");
				return false;
			}
			
			Whois_Driver whois_driver = new Whois_Driver(fle, Whois_Driver.EXECUTION_ACTION_DETERMINE_LIST_OF_TLD_REGISTRARS);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "determine_tld_registrar", e);
		}
		
		return false;
	}
	
	
	
	public boolean store_tld_registrar_list()
	{
		try
		{
			File fle = driver.querySelectFile(true, "Please specify list of TLDs to store...", JFileChooser.FILES_ONLY, false, false);
			
			if(fle == null || !fle.exists())
			{
				driver.directive("ERROR!!! NO FILE SELECTED!");
				return false;
			}
			
			Whois_Driver whois_driver = new Whois_Driver(fle, Whois_Driver.EXECUTION_ACTION_STORE_LIST_OF_TLD_REGISTRARS);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_tld_registrar_list", e);
		}
		
		return false;
	}
	
	
	
	
	
	
	
	
	/**
	 * Change this either in Driver or in Whois proper class
	 * @param lookup
	 * @return
	 */
	public String normalize_lookup(String lookup)
	{
		try
		{
			lookup = lookup.trim();
			
			if(lookup.toLowerCase().startsWith("https://"))
				lookup = lookup.substring(8).trim();
			if(lookup.toLowerCase().startsWith("http://"))
				lookup = lookup.substring(7).trim();
			if(lookup.toLowerCase().startsWith("www."))
				lookup = lookup.substring(4).trim();
			if(lookup.toLowerCase().startsWith("/"))
				lookup = lookup.substring(1).trim();
			if(lookup.toLowerCase().startsWith("/"))
				lookup = lookup.substring(1).trim();
			if(lookup.toLowerCase().startsWith("."))
				lookup = lookup.substring(1).trim();
			
			//bifurcate domain name from URL
			if(lookup.contains("/"))
			{
				arr = lookup.split("\\/");				
				
				if(arr[0] != null && !arr[0].trim().equals(""))
					lookup = arr[0].trim();
				else if(arr.length > 1 && arr[2] != null && !arr[2].trim().equals(""))
					lookup = arr[0].trim();				
			}
			
			
			//drop subdomains
			arr = lookup.split("\\.");
			
			//check if we may have an ip address
			if(arr != null && arr.length > 3)
			{
				try
				{
					Integer.parseInt(arr[0].trim());
					Integer.parseInt(arr[1].trim());
					Integer.parseInt(arr[2].trim());
					Integer.parseInt(arr[3].trim());
					
					//first 4 octets are ip addresses					
					lookup = arr[0].trim() + "." + arr[1].trim() + "." +arr[2].trim() + "." +arr[3].trim();
				}
				catch(Exception e)
				{
					//something went wrong, so consider it a subdomain...
					if(arr != null && arr.length > 1)
						lookup = arr[arr.length-2] + "." + arr[arr.length-1];
				}
			}
			
			//not ip address, thus remove subdomains
			else if(arr != null && arr.length > 1)
				lookup = arr[arr.length-2] + "." + arr[arr.length-1];
			
			lookup = lookup.trim();			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "normalize_lookup", e);
		}
		
		return lookup;
	}
	
	
	public static boolean displayHelp()
	{
		try
		{
			for(String line : arrHelp)
				driver.directive(line);
			
			driver.directive("");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "displayHelp", e);
		}
		
		return false;
	}
	
}
