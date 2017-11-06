/**
 * @author Solomon Sonya
 */


package whois;

import Driver.*;
import Node.Node_GeoIP;
import Node.Node_Nslookup;

import java.util.*;
import java.io.*;
import java.net.*;

/**
 * Main class for instance, provide a list of domains to resolve. This driver handles passing the domains into each whois resolution
 * @author Solomon Sonya
 *
 */

public class Whois_Driver extends Thread implements Runnable
{
	public static final String myClassName = "Whois_Driver";
	public static volatile Driver driver = new Driver();

	/**Just a lookup table of knowing if we have attempted to resolve a domain already*/
	public static volatile TreeMap<String, String> tree_whois_lookup_domain_names_hashes = new TreeMap<String,String>();
	
	public static final boolean PERFORM_GEO_IF_NOT_SPECIFIED = false;
	
	public static final String [] arrCommon_TLDs = new String[]
			{ "com", "org", "gov", "me", "ws", "net", "edu", "biz", "cn", "us", "info", "ca", "de", "jp", "fr"};
	
	/**	 
	 	TLD Whois registrar for [org] --> whois.pir.org
		TLD Whois registrar for [fr] --> whois.nic.fr
		TLD Whois registrar for [cn] --> whois.cnnic.cn
		TLD Whois registrar for [ca] --> whois.cira.ca
		TLD Whois registrar for [com] --> whois.verisign-grs.com
		TLD Whois registrar for [ws] --> whois.website.ws
		TLD Whois registrar for [info] --> whois.afilias.net
		TLD Whois registrar for [me] --> whois.nic.me
		TLD Whois registrar for [jp] --> whois.jprs.jp
		TLD Whois registrar for [edu] --> whois.educause.edu
		TLD Whois registrar for [co] --> whois.nic.co
		TLD Whois registrar for [us] --> whois.nic.us
		TLD Whois registrar for [uk] --> whois.nic.uk
		TLD Whois registrar for [de] --> whois.denic.de
		TLD Whois registrar for [biz] --> whois.biz
		TLD Whois registrar for [net] --> whois.verisign-grs.com
		TLD Whois registrar for [gov] --> whois.dotgov.gov
	 */
	
	public volatile File fleWhoisLookupTable = null;
	
	public static final int EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR = 1;
	public static final int EXECUTION_ACTION_DETERMINE_LIST_OF_TLD_REGISTRARS = 2;
	public static final int EXECUTION_ACTION_STORE_LIST_OF_TLD_REGISTRARS = 3;
	public static final int EXECUTION_ACTION_DERIVE_REGISTRAR_WHOIS_SERVER = 4;
	public static final int EXECUTION_ACTION_PERFORM_WHOIS_LOOKUP = 5;
	public static final int EXECUTION_ACTION_DERIVE_WHOIS_REGISTRATION_INFO_FROM_DOMAIN_NAME_LIST = 6;
	public static final int EXECUTION_ACTION_CACHE_MOST_COMMON_TLDS = 7;
	public static final int EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR_SURPRESS_OUTPUT = 8;
	public static final int EXECUTION_ACTION_INGEST_DIRECTORY_OF_WHOIS_FILES = 9;
	public static final int EXECUTION_ACTION_IMPORT_EXCALIBUR_WHOIS_DATA_FILE = 10;
	
	public int myExecutionAction = 0;
	
	public volatile String LOOKUP = null;
	public volatile File fleImport = null;
	
	public volatile String [] array = null;
	
	public Whois_Driver(File fle)
	{
		try
		{
			fleWhoisLookupTable = fle;
			
			if(fleWhoisLookupTable != null && fleWhoisLookupTable.exists() && fle.isFile())
			{
				this.start();
			}
			
			else
				driver.directive("PUNT! Unable to start whois resolution.  File appears to be null or no longer valid <" + fle + ">");
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public Whois_Driver(String LookUp, int EXEC_ACTION)
	{
		try
		{
			myExecutionAction = EXEC_ACTION;
			LOOKUP = LookUp;
			
			this.start();
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	public Whois_Driver(File fle, int EXEC_ACTION)
	{
		try
		{
			myExecutionAction = EXEC_ACTION;
			fleImport = fle;
			
			this.start();
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
		}
	}
	
	public Whois_Driver(String [] arr, int EXEC_ACTION)
	{
		try
		{
			myExecutionAction = EXEC_ACTION;
			array = arr;
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 4", e);
		}
				
	}
	
	public void run()
	{
		try
		{
			if(fleWhoisLookupTable != null && fleWhoisLookupTable.exists() && fleWhoisLookupTable.isFile())
			{
				import_lookup_file(fleWhoisLookupTable);
			}
			
			else
			{
				switch(myExecutionAction)
				{
					case EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR:
					{
						//return IANA information to reach a TLD
						Whois whois = new Whois(LOOKUP, EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR);
						break;
					}
					
					case EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR_SURPRESS_OUTPUT:
					{
						//return IANA information to reach a TLD
						Whois whois = new Whois(LOOKUP, EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR_SURPRESS_OUTPUT);
						break;
					}
					
					case EXECUTION_ACTION_DETERMINE_LIST_OF_TLD_REGISTRARS:
					{
						import_tld_file_list(this.fleImport);
						break;
					}
					
					case EXECUTION_ACTION_STORE_LIST_OF_TLD_REGISTRARS:
					{
						store_tld_file_list(this.fleImport);
						break;
					}
					
					case EXECUTION_ACTION_DERIVE_REGISTRAR_WHOIS_SERVER:
					{
						Whois whois = new Whois(LOOKUP, EXECUTION_ACTION_DERIVE_REGISTRAR_WHOIS_SERVER);
						break;
					}
					
					case EXECUTION_ACTION_PERFORM_WHOIS_LOOKUP:
					{
						Whois whois = new Whois(LOOKUP, EXECUTION_ACTION_PERFORM_WHOIS_LOOKUP);
						break;
					}
					
					case EXECUTION_ACTION_DERIVE_WHOIS_REGISTRATION_INFO_FROM_DOMAIN_NAME_LIST:
					{
						import_whois_domain_name_file_list_to_derive(this.fleImport);
						break;
					}
					
					case EXECUTION_ACTION_CACHE_MOST_COMMON_TLDS:
					{
						cache_most_popular_tlds(this.array);
						break;
					}
					
					case EXECUTION_ACTION_INGEST_DIRECTORY_OF_WHOIS_FILES:
					{
						ingest_directory_of_whois_files(this.fleImport);
						break;
					}
					
					case EXECUTION_ACTION_IMPORT_EXCALIBUR_WHOIS_DATA_FILE:
					{
						import_excalibur_whois_data_file(this.fleImport, "\t");
						break;
					}
					
				}
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	
	/*
	 * expects a directory populated with files e.g. google.com.txt, yahoo.com.txt, etc with each one containing full contants of the whois retrieval
	 */
	public boolean ingest_directory_of_whois_files(File fle)
	{
		try
		{
			int count = 0;
			//get directory listing
			LinkedList<File> listing = new LinkedList<File>();
			listing = driver.getFileListing(fle, true, null, listing);
			
			if(listing == null || listing.size() < 1)
			{
				driver.directive("PUNT! Unable to continue: Specified directory returned 0 elements -->" + fle);
				return false;
			}
			
			driver.directive("Attempting to analyze excalibur_whois files under directory: " + fle.getCanonicalPath());
			String line = "";
			Whois whois = null;
			//else, analyze each file
			for(File excalibur : listing)
			{
				try
				{
					if(excalibur == null || !excalibur.isFile() || !excalibur.isFile() )
						continue;
					
					++count;
					
					driver.directive("[" + count + "]\t " + (((0.0 + count) / (0.0 + listing.size())) * 100)  + "%\t Analyzing whois file --> " + excalibur.getCanonicalPath());
					
					BufferedReader brIn = new BufferedReader(new FileReader(excalibur));
					whois = new Whois();
					String [] arr2 = null;
					while((line = brIn.readLine()) != null)
					{
						if(line.trim().equals(""))
							continue;
						
						if(line.contains("Name Server IP:"))
						{
							arr2 = line.split("Name Server IP:");
							
							for(String key : arr2)
								whois.parse_whois_server("Name Server IP: " + key.replaceAll(whois.delimiter1, ""));
							
							continue;
						}
						
						else if(line.contains("Name Server:"))
						{
							arr2 = line.split("Name Server:");
							
							for(String key : arr2)
								whois.parse_whois_server("Name Server: " + key.replaceAll(whois.delimiter1, ""));
							
							continue;
						}
						
						else if(line.contains("Domain Status:"))
						{
							arr2 = line.split("Domain Status:");
							
							for(String key : arr2)
								whois.parse_whois_server("Domain Status: " + key.replaceAll(whois.delimiter1, ""));
							
							continue;
						}
						
						else if(line.contains(whois.delimiter1))
						{
							driver.directive(line);
							
							arr2 = line.split(whois.delimiter1);
							
							for(String key : arr2)
								whois.parse_whois_server(key);
							
							continue;
						}
						
						//
						//parse each line
						//
						whois.parse_whois_server(line);
					}
					
					//finished
					try	{	brIn.close();}catch(Exception e){}

					//e.g. for .biz
					if(whois.REGISTRAR_WHOIS_SERVER == null || whois.REGISTRAR_WHOIS_SERVER.trim().equals(""))
					{
						whois.REGISTRAR_WHOIS_SERVER = whois.registrar_whois_server;
					}

					if(whois.DOMAIN_NAME == null || whois.DOMAIN_NAME.trim().equals(""))
					{
						whois.DOMAIN_NAME = whois.domain_name;
					}

					if(whois.TLD_WHOIS_REGISTRAR == null || whois.TLD_WHOIS_REGISTRAR.trim().equals(""))
					{
						//whois.TLD_WHOIS_REGISTRAR = whois.tld;
					}

					if(PERFORM_GEO_IF_NOT_SPECIFIED && whois.node_geo == null)
						whois.node_geo = Node_GeoIP.resolve(whois.domain_name, false);

					//analyze the IP, if it appears to be IPv6, then try to submit a new request for a specific IP address if we have it
					if(PERFORM_GEO_IF_NOT_SPECIFIED && whois.node_geo != null && whois.node_geo.ip != null && whois.node_geo.ip.contains(":") && whois.name_server_IP1 != null && !whois.name_server_IP1.trim().equals(""))
					{
						//try again with this new ip, but not with the potential ipv6
						whois.node_geo = Node_GeoIP.resolve(whois.name_server_IP1, false);
					}
					
					//analyze
					if(whois.domain_name != null && !whois.domain_name.trim().equals("") && !Whois.tree_whois_lookup.containsKey(whois.domain_name.toLowerCase().trim()))
					{
						Whois.tree_whois_lookup.put(whois.domain_name.toLowerCase().trim(), whois);
						
						//
						//LOG!!!!
						//
						if(Whois.log_excalibur_whois_data_line == null)
						{
							Whois.log_excalibur_whois_data_line = new Log("excalibur_whois_data_file",  "excalibur_whois_data_file", 250, 999999999);
							Whois.log_excalibur_whois_data_line.log(whois.get_whois_line_file_header("\t"));
						}

						//log based on if we have geo and nslookup data
						if(whois.node_geo != null && whois.node_nslookup != null)
							Whois.log_excalibur_whois_data_line.log(whois.get_whois_data_line("\t", whois.node_nslookup.get_details(true, ":", "\t"), whois.node_geo.get_details(true, ":", "\t")));
						else if(whois.node_geo != null)
							Whois.log_excalibur_whois_data_line.log(whois.get_whois_data_line("\t", Node_Nslookup.BLANK_ROW, whois.node_geo.get_details(true, ":", "\t")));
						else if(whois.node_nslookup != null)
							Whois.log_excalibur_whois_data_line.log(whois.get_whois_data_line("\t", whois.node_nslookup.get_details(true, ":", "\t"), Node_GeoIP.BLANK_ROW));


					}
					
					
					
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "ingest_directory_of_whois_files on file -->" + excalibur, e, -1);
					continue;
				}
			}
			
			driver.directive("Process complete. Num files processed: [" + count + "] on directory --> " + fle);
			driver.directive("Size of whois cache: [" + Whois.tree_whois_lookup.size() + "]");
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "ingest_directory_of_whois_files", e);
		}
		
		return false;
	}
	
	public boolean cache_most_popular_tlds(String [] arr)
	{
		try
		{
			if(arr == null || arr.length < 1)
				return false;
			
			driver.directive("Caching most popular TLDs. Please standby...");
			
			//suspend output
			
			
			for(String tld : arr)
			{
				Whois_Driver whois_driver = new Whois_Driver(tld, Whois_Driver.EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR_SURPRESS_OUTPUT);
			}
			
			driver.directive("Complete. Run the help command for additional instructions...");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "cache_most_popular_tlds", e);
		}
		
		return false;
	}
	
	public boolean import_tld_file_list(File fle)
	{
		try
		{
			if(fle == null || !fle.exists())
			{
				driver.directive("PUNT! Invalid file specified for import_tld_file");
				return false;
			}

			//EXPECT each TLD to be on new line
			
			int line_count = 0;
			
			driver.directive("Attempting to open file -->" + fle.getCanonicalPath());
			
			BufferedReader brIn = new BufferedReader(new FileReader(fle));			
			String line = "";
			
			while((line = brIn.readLine()) != null)
			{
				line = line.toLowerCase().trim();
				++line_count;
				
				if(line.startsWith("."))
					line = line.substring(1).trim();
				
				if(line.equals(""))
					continue;
				
				//check if we've seen it before
				if(Whois.cache_IANA_TLD.containsKey(line))
					continue;
				
				//otw, perform the lookups
				Whois whois = new Whois(line, EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR);
			}

			try	{	brIn.close();}catch(Exception e){}
			
			driver.directive("Import TLD Registrar to retrieve list complete. Num Lines read [" + fle.getCanonicalPath() + "] --> " + line_count);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_tld_file_list", e);
		}
		
		return false;
	}
	
	public boolean import_excalibur_whois_data_file(File excalibur, String delimiter)
	{
		try
		{
			int count = 0;
			
			if(excalibur == null || !excalibur.exists() || !excalibur.isFile())
			{
				driver.directive("PUNT!!! INVALID FILE SPECIFIED IN IMPORT EXCALIBUR WHOIS DATA FILE!");
				return false;
			}
			
			driver.directive("Attempting to analyze excalibur_whois data file --> " + excalibur.getCanonicalPath());
			String line = "";
			Whois whois = null;
			//else, analyze each file			
			
			BufferedReader brIn = new BufferedReader(new FileReader(excalibur));
			whois = new Whois();
			String [] arr = null;
			String [] arr2 = null;
			
			
			//omit first line
			brIn.readLine();
			
			while((line = brIn.readLine()) != null)
			{
				++count;
				
				if(line.trim().equals(""))
					continue;

				
				//split the line and parse the tokens
				arr = line.split(delimiter);
				
				if(arr == null || arr.length < 1)
					continue;
				
				//need to split domain_status, name_server, and name_server_ips
				
				
				
				for(String token : arr)				
				{
					if(token.trim().equals(""))
						continue;
					
					if(token.contains("Name Server IP:"))
					{
						arr2 = token.split("Name Server IP:");
						
						for(String key : arr2)
							whois.parse_whois_server("Name Server IP: " + key.replaceAll(whois.delimiter1, ""));
						
						continue;
					}
					
					else if(token.contains("Name Server:"))
					{
						arr2 = token.split("Name Server:");
						
						for(String key : arr2)
							whois.parse_whois_server("Name Server: " + key.replaceAll(whois.delimiter1, ""));
						
						continue;
					}
					
					else if(token.contains("Domain Status:"))
					{
						arr2 = token.split("Domain Status:");
						
						for(String key : arr2)
							whois.parse_whois_server("Domain Status: " + key.replaceAll(whois.delimiter1, ""));
						
						continue;
					}
					
					else if(token.contains(whois.delimiter1))
					{
						driver.directive(token);
						
						arr2 = token.split(whois.delimiter1);
						
						for(String key : arr2)
							whois.parse_whois_server(key);
						
						continue;
					}
					
					//
					//OTW
					//
					
					whois.parse_whois_server(token);
				}
				
				if(whois.domain_name != null && !whois.domain_name.trim().equals(""))
					driver.directive("\t Analyzed domain name: " + whois.domain_name);
				
				//e.g. for .biz
				if(whois.REGISTRAR_WHOIS_SERVER == null || whois.REGISTRAR_WHOIS_SERVER.trim().equals(""))
				{
					whois.REGISTRAR_WHOIS_SERVER = whois.registrar_whois_server;
				}

				if(whois.DOMAIN_NAME == null || whois.DOMAIN_NAME.trim().equals(""))
				{
					whois.DOMAIN_NAME = whois.domain_name;
				}

				if(whois.TLD_WHOIS_REGISTRAR == null || whois.TLD_WHOIS_REGISTRAR.trim().equals(""))
				{
					//whois.TLD_WHOIS_REGISTRAR = whois.tld;
				}

				if(PERFORM_GEO_IF_NOT_SPECIFIED && whois.node_geo == null)
					whois.node_geo = Node_GeoIP.resolve(whois.domain_name, false);

				//analyze the IP, if it appears to be IPv6, then try to submit a new request for a specific IP address if we have it
				if(PERFORM_GEO_IF_NOT_SPECIFIED && whois.node_geo != null && whois.node_geo.ip != null && whois.node_geo.ip.contains(":") && whois.name_server_IP1 != null && !whois.name_server_IP1.trim().equals(""))
				{
					//try again with this new ip, but not with the potential ipv6
					whois.node_geo = Node_GeoIP.resolve(whois.name_server_IP1, false);
				}
				
				//analyze
				if(whois.domain_name != null && !whois.domain_name.trim().equals("") && !Whois.tree_whois_lookup.containsKey(whois.domain_name.toLowerCase().trim()))
				{
					Whois.tree_whois_lookup.put(whois.domain_name.toLowerCase().trim(), whois);
					
					//
					//LOG!!!!
					//
					if(Whois.log_excalibur_whois_data_line == null)
					{
						Whois.log_excalibur_whois_data_line = new Log("excalibur_whois_data_file",  "excalibur_whois_data_file", 250, 999999999);
						Whois.log_excalibur_whois_data_line.log(whois.get_whois_line_file_header("\t"));
					}

					//log based on if we have geo and nslookup data
					if(whois.node_geo != null && whois.node_nslookup != null)
						Whois.log_excalibur_whois_data_line.log(whois.get_whois_data_line("\t", whois.node_nslookup.get_details(true, ":", "\t"), whois.node_geo.get_details(true, ":", "\t")));
					else if(whois.node_geo != null)
						Whois.log_excalibur_whois_data_line.log(whois.get_whois_data_line("\t", Node_Nslookup.BLANK_ROW, whois.node_geo.get_details(true, ":", "\t")));
					else if(whois.node_nslookup != null)
						Whois.log_excalibur_whois_data_line.log(whois.get_whois_data_line("\t", whois.node_nslookup.get_details(true, ":", "\t"), Node_GeoIP.BLANK_ROW));


				}

				
			}

			//finished
			try	{	brIn.close();}catch(Exception e){}

			
			

			



			driver.directive("Process complete. Num files processed: [" + count + "] on directory --> " + excalibur);
			driver.directive("Size of whois cache: [" + Whois.tree_whois_lookup.size() + "]");

			return true;
		}

		catch(Exception e)
		{
			driver.eop(myClassName, "import_excalibur_whois_data_file", e);
		}

		return false;
	}


	public boolean import_whois_domain_name_file_list_to_derive(File fle)
	{
		try
		{
			if(fle == null || !fle.exists())
			{
				driver.directive("* PUNT! Invalid file specified for import_whois_domain_name_file_list_to_derive");
				return false;
			}

			//EXPECT each TLD to be on new line

			int line_count = 0;

			driver.directive("Attempting to open file -->" + fle.getCanonicalPath());

			BufferedReader brIn = new BufferedReader(new FileReader(fle));			
			String line = "";

			while((line = brIn.readLine()) != null)
			{
				line = line.toLowerCase().trim();
				++line_count;

				if(line.startsWith("."))
					line = line.substring(1).trim();

				if(line.equals(""))
					continue;

				if(line.startsWith("#") || line.startsWith("\\#"))
					continue;

				//check if we've seen it before
				if(Whois.tree_whois_lookup.containsKey(line))
					continue;

				driver.sp("[" + line_count + "]\t");

				//otw, perform the lookups
				Whois whois = new Whois(line, EXECUTION_ACTION_PERFORM_WHOIS_LOOKUP, false);
			}

			try	{	brIn.close();}catch(Exception e){}

			driver.directive("Import Domain Name list to derive whois registration information complete. Num Lines read [" + fle.getCanonicalPath() + "] --> " + line_count);

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_whois_domain_name_file_list_to_derive", e);
		}

		return false;
	}

	public boolean import_lookup_file(File fle)
	{
		try
		{
			int line_count = 0;


			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_lookup_file", e);
		}

		return false;
	}

	/**
	 * Store already derived list of tld's in format <tld>	<tld whois registrar> e.g. com	whois.verisign-grs.com
	 * @param fle
	 * @return
	 */
	public boolean store_tld_file_list(File fle)
	{
		try
		{
			if(fle == null || !fle.exists())
			{
				driver.directive("PUNT!!! Invalid file specified for import_tld_file");
				return false;
			}

			//EXPECT each TLD to be on new line

			int line_count = 0;

			driver.directive("Attempting to open file -->" + fle.getCanonicalPath());

			BufferedReader brIn = new BufferedReader(new FileReader(fle));			
			String line = "";

			String tld = "", tld_registrar = "";
			String [] arr = null;

			while((line = brIn.readLine()) != null)
			{
				try
				{
					line = line.toLowerCase().trim();
					++line_count;

					if(line.startsWith("."))
						line = line.substring(1).trim();

					if(line.equals(""))
						continue;

					arr = line.split("\t");

					if(arr == null || arr.length < 2)
					{
						driver.directive("Skipping line [" + line_count + "] - invalid format...");
						continue;
					}

					//bifurcate tld from tld registrar
					tld = arr[0].trim();
					tld_registrar = arr[1].trim();

					if(tld.trim().equals("") || tld_registrar.trim().equals(""))
					{
						driver.directive("--Skipping line [" + line_count + "] - invalid format... tld -->" + tld + "<-- tld_registrar -->" + tld_registrar + "<--");
						continue;
					}

					//check if we've seen it before
					if(Whois.cache_IANA_TLD.containsKey(tld))
						continue;

					//otw, store it!
					Whois whois = new Whois(tld, tld_registrar, EXECUTION_ACTION_STORE_LIST_OF_TLD_REGISTRARS);


				}

				catch(Exception e)
				{
					driver.eop_loop(myClassName, "store_tld_import_file", e, line_count);
					continue;
				}


			}

			try	{	brIn.close();}catch(Exception e){}

			driver.directive("Import TLD Registrar to retrieve list complete. Num Lines read [" + fle.getCanonicalPath() + "] --> " + line_count);

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "store_tld_file_list", e);
		}

		return false;
	}



























































}
