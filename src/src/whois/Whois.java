/**
 * @author Solomon Sonya
 * 
 * note:
 * 
 * registry_domain_id == domain_id
 * registrar_registration_expiration_date == registry_expiry_date
 * registrar == sponsoring_registrar
 * registrar_iana_id == sponsoring_registrar_iana_id
 * whois_server == //.info whois

	NOTE: need to come back and parse:
		.co domains
		.uk

 */

package whois;

import Driver.*;
import Node.Node_GeoIP;
import Node.Node_Nslookup;

import java.util.*;
import java.io.*;
import java.net.*;

public class Whois extends Thread implements Runnable
{
	public static final String myClassName = "whois";
	public static volatile Driver driver = new Driver();
	
	public static final String delimiter1 = "#####";
	
	public static volatile boolean STORE_WHOIS = true;
	public static volatile boolean debug = true;
	public volatile Node_GeoIP node_geo = null;
	public volatile Node_Nslookup node_nslookup = null;
	
	public volatile String value = "";
	
	public static final int SOCKET_TIMEOUT = 15*1000;
	
	public static final int PING_COUNT = 2;
	
	/**Contains whois server for COM, NET, ORG, etc*/
	public static volatile TreeMap<String, Whois> cache_IANA_TLD = new TreeMap<String, Whois>();
	
	/**Contains whois registrar servers for google.com eg. whois.markmonitor.com*/
	public static volatile TreeMap<String, Whois> tree_whois_registrar_server = new TreeMap<String, Whois>();
	
	/**Contains whois record for google.com, yahoo.com, bing.com, etc*/
	public static volatile TreeMap<String, Whois> tree_whois_lookup = new TreeMap<String, Whois>();
	
	public volatile String [] arr = null;
	public volatile boolean surpress_output = false;
	
	public volatile int EXECUTION_ACTION = 0;
	public String LOOKUP = null;
	
	public static final String WHOIS_IANA_ORG = "whois.iana.org";
	public static final int PORT_WHOIS = 43;
	public volatile String LOOKUP_ORIGINAL = "";
	
	public volatile String ping_command = "";
	
	/**google.com*/
	public volatile String DOMAIN_NAME = null;
	
	/**e.g. COM from google.com*/
	public volatile String TLD = null;
	
	/**e.g. whois:        whois.verisign-grs.com*/
	public volatile String TLD_WHOIS_REGISTRAR_FULL_LINE = null;
	
	/**e.g. whois.verisign-grs.com*/
	public volatile String TLD_WHOIS_REGISTRAR = null;
	
	/**e.g. whois.markmonitor.com*/
	public volatile String REGISTRAR_WHOIS_SERVER = null;
	
	public static volatile Log log_tld_all = null;
	public static volatile Log log_tld_registrar_not_found = null;
	public static volatile Log log_excalibur_whois_data_line = null; 
	public static volatile Log log_domain_name_not_found = null;
	
	/**DUPLICATE EXISTS! all caps is what we searched and normalized for. lowercase is what we paresed directly from server*/
	public volatile String domain_name = null;
	public volatile String registry_domain_id = null;
	/**DUPLICATE EXISTS! all caps is what we searched and normalized for. lowercase is what we paresed directly from server*/
	public volatile String registrar_whois_server = null;
	public volatile String registrar_url = null;
	public volatile String updated_date = null;
	public volatile String creation_date = null;
	public volatile String registrar_registration_expiration_date = null;
	public volatile String registrar = null;
	public volatile String registrar_iana_id = null;
	public volatile String registrar_abuse_contact_email = null;
	public volatile String registrar_abuse_contact_phone = null;
	public volatile String registrar_abuse_contact_ext = null;
	public volatile String domain_status1 = null;
	public volatile String domain_status2 = null;
	public volatile String domain_status3 = null;
	public volatile String domain_status4 = null;
	public volatile String domain_status5 = null;
	public volatile String domain_status6 = null;
	public volatile String domain_status7 = null;
	public volatile String domain_status8 = null;
	public volatile String domain_status9 = null;
	public volatile String domain_status10 = null;
	public volatile String name_server_NAME1 = null;
	public volatile String name_server_NAME2 = null;
	public volatile String name_server_NAME3 = null;
	public volatile String name_server_NAME4 = null;
	public volatile String name_server_NAME5 = null;
	public volatile String name_server_NAME6 = null;
	public volatile String name_server_NAME7 = null;
	public volatile String name_server_NAME8 = null;
	public volatile String name_server_NAME9 = null;
	public volatile String name_server_NAME10 = null;
	public volatile String name_server_NAME11 = null;
	public volatile String name_server_NAME12 = null;
	public volatile String name_server_NAME13 = null;
	public volatile String name_server_NAME14 = null;
	public volatile String name_server_NAME15 = null;
	public volatile String name_server_NAME16 = null;
	public volatile String name_server_NAME17 = null;
	public volatile String name_server_NAME18 = null;
	public volatile String name_server_NAME19 = null;
	public volatile String name_server_NAME20 = null;
	public volatile String name_server_IP1 = null;
	public volatile String name_server_IP2 = null;
	public volatile String name_server_IP3 = null;
	public volatile String name_server_IP4 = null;
	public volatile String name_server_IP5 = null;
	public volatile String name_server_IP6 = null;
	public volatile String name_server_IP7 = null;
	public volatile String name_server_IP8 = null;
	public volatile String name_server_IP9 = null;
	public volatile String name_server_IP10 = null;
	public volatile String name_server_IP11 = null;
	public volatile String name_server_IP12 = null;
	public volatile String name_server_IP13 = null;
	public volatile String name_server_IP14 = null;
	public volatile String name_server_IP15 = null;
	public volatile String name_server_IP16 = null;
	public volatile String name_server_IP17 = null;
	public volatile String name_server_IP18 = null;
	public volatile String name_server_IP19 = null;
	public volatile String name_server_IP20 = null;
	public volatile String dnssec = null;

	
	public volatile String  whois_server = null;
	public volatile String  referral_url = null;
	public volatile String  registry_registrant_id = null;
	public volatile String  registrant_name = null;
	public volatile String  registrant_organization = null;
	public volatile String  registrant_street = null;
	public volatile String  registrant_city = null;
	public volatile String  registrant_state_province = null;
	public volatile String  registrant_postal_code = null;
	public volatile String  registrant_country = null;
	public volatile String  registrant_phone = null;
	public volatile String  registrant_phone_ext = "";
	public volatile String  registrant_fax = "";
	public volatile String  registrant_fax_ext = "";
	public volatile String  registrant_email = "";
	public volatile String  registry_admin_id = null;
	public volatile String  admin_name = null;
	public volatile String  admin_organization = null;
	public volatile String  admin_street = null;
	public volatile String  admin_city = null;
	public volatile String  admin_state_province = null;
	public volatile String  admin_postal_code = null;
	public volatile String  admin_country = null;
	public volatile String  admin_phone = "";
	public volatile String  admin_phone_ext = "";
	public volatile String  admin_fax = "";
	public volatile String  admin_fax_ext = "";
	public volatile String  admin_email = null;
	public volatile String  registry_tech_id = null;
	public volatile String  tech_name = null;
	public volatile String  tech_organization = null;
	public volatile String  tech_street = null;
	public volatile String  tech_city = null;
	public volatile String  tech_state_province = null;
	public volatile String  tech_postal_code = null;
	public volatile String  tech_country = null;
	public volatile String  tech_phone = "";
	public volatile String  tech_phone_ext = "";
	public volatile String  tech_fax = "";
	public volatile String  tech_fax_ext = "";
	public volatile String  tech_email = null;
	/**.INFO*/
	public volatile String  billing_id = null;
	/**.INFO*/
	public volatile String  billing_name = null;
	/**.INFO*/
	public volatile String  billing_organization = null;
	/**.INFO*/
	public volatile String  billing_street = null;
	/**.INFO*/
	public volatile String  billing_city = null;
	/**.INFO*/
	public volatile String  billing_state_province = null;
	/**.INFO*/
	public volatile String  billing_postal_code = null;
	/**.INFO*/
	public volatile String  billing_country = null;
	/**.INFO*/
	public volatile String  billing_phone = null;
	/**.INFO*/
	public volatile String  billing_phone_ext = null;
	/**.INFO*/
	public volatile String  billing_fax = null;
	/**.INFO*/
	public volatile String  billing_fax_ext = null;
	
	
	public volatile String  first_lookup_date = driver.time.getTime_Current_Hyphenated(false);
	public volatile String  last_lookup_date = driver.time.getTime_Current_Hyphenated(false);
	public volatile long first_lookup_date_millis = System.currentTimeMillis();
	public volatile long last_lookup_date_millis = System.currentTimeMillis();
	
	
	/**We have room for 10 - 20 name servers, but only return a list of the allocated servers*/
	public volatile String name_server_concat = null;
	
	/**We have room for 5 - 10 domain status indicators but only return a list of the allocated status*/
	public volatile String domain_status_concat = null;
	
	public Whois()//null constructor
	{
		try
		{
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 0", e);
		}
	}
	
	public Whois(String lookup, int execution_action, boolean start_thread)
	{
		try
		{
			LOOKUP = lookup;
			EXECUTION_ACTION = execution_action;
			LOOKUP_ORIGINAL = lookup;
			
			if(start_thread)
				this.start();
			else
				this.commence_execution_action();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public Whois(String lookup, int execution_action)
	{
		try
		{
			LOOKUP = lookup;
			EXECUTION_ACTION = execution_action;
			LOOKUP_ORIGINAL = lookup;
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	public Whois(String tld, String tld_registrar, int execution_action)
	{
		try
		{
			TLD = tld; 
			TLD_WHOIS_REGISTRAR = tld_registrar;
			EXECUTION_ACTION = execution_action;
			
			//add self to cache
			if(TLD != null && !TLD.trim().equals("") && TLD_WHOIS_REGISTRAR != null && !TLD_WHOIS_REGISTRAR.equals("") && !cache_IANA_TLD.containsKey(TLD))
			{
				TLD = TLD.toLowerCase().trim();
				TLD_WHOIS_REGISTRAR = TLD_WHOIS_REGISTRAR.trim();
				
				cache_IANA_TLD.put(TLD, this);
			}
			
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
		}
	}
	
	
	
	
	public void run()
	{
		try
		{
			commence_execution_action();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public String normalize_lookup(String lookup)
	{
		try
		{
			this.LOOKUP_ORIGINAL = lookup;
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
				this.arr = lookup.split("\\/");				
				
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
	
	public boolean commence_execution_action()
	{
		try
		{
			LOOKUP = normalize_lookup(LOOKUP);
											
			switch(EXECUTION_ACTION)
			{
				case Whois_Driver.EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR:
				{
					String registrar = derive_TLD_REGISTRAR_from_IANA(WHOIS_IANA_ORG, PORT_WHOIS, LOOKUP);
					
					if(registrar == null)
					{
						if(log_tld_registrar_not_found == null)
							log_tld_registrar_not_found = new Log("tld_registrars",  "TLD_REGISTRAR_NOT_FOUND", 250, 999999999);
						
						log_tld_registrar_not_found.log(LOOKUP);
						
						driver.directive("ERROR! no registrar was found for [" + LOOKUP + "]");
						
					}
					else
						driver.directive("TLD Whois registrar for [" + LOOKUP + "] --> " + registrar);
					
					break;
				}
				
				case Whois_Driver.EXECUTION_ACTION_RETURN_TLD_IANA_REGISTRAR_SURPRESS_OUTPUT:
				{
					
					surpress_output = true;
					
					String registrar = derive_TLD_REGISTRAR_from_IANA(WHOIS_IANA_ORG, PORT_WHOIS, LOOKUP);
					
					if(registrar == null)
					{
						if(log_tld_registrar_not_found == null)
							log_tld_registrar_not_found = new Log("tld_registrars",  "TLD_REGISTRAR_NOT_FOUND", 250, 999999999);
						
						log_tld_registrar_not_found.log(LOOKUP);
						
						driver.directive("ERROR! no registrar was found for [" + LOOKUP + "]");
						
					}
					else
						driver.directive("TLD Whois registrar for [" + LOOKUP + "] --> " + registrar);
					
					break;
				}
				
				case Whois_Driver.EXECUTION_ACTION_DERIVE_REGISTRAR_WHOIS_SERVER:
				{
					String registrar_whois_server = derive_REGISTRAR_WHOIS_SERVER(WHOIS_IANA_ORG, PORT_WHOIS, LOOKUP);
					
					if(registrar_whois_server == null)
						driver.directive("whois registrar server not found for -->" + LOOKUP);
					else
						driver.directive("Whois registrar server for [" + LOOKUP + "] -->" + registrar_whois_server);
					
				}
				
				case Whois_Driver.EXECUTION_ACTION_PERFORM_WHOIS_LOOKUP:
				{
					if(this.tree_whois_lookup.containsKey(LOOKUP.toLowerCase().trim()))
						this.tree_whois_lookup.get(LOOKUP.toLowerCase().trim()).print_whois("\n");
					else
					{
						boolean status = whois(WHOIS_IANA_ORG, PORT_WHOIS, LOOKUP);
						
						if(status)
						{
							print_whois("\n");
							
							write_excalibur_whois_log();
						}
						else
						{
							driver.directive("PUNT!! Unable to derive Whois registration informaiton from [" + LOOKUP + "].");
							
							if(log_domain_name_not_found == null)
								log_domain_name_not_found = new Log("domain_names_not_found",  "domain_names_not_found", 250, 999999999);
							
							log_domain_name_not_found.log(LOOKUP);
						}
					}
					
					
				}
			
			}
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "commence_execution_action", e);
		}
		
		return false;
	}
	
	/**
	 * just a helper function...
	 * @param lookup
	 * @return
	 */
	public boolean set_TLD_and_DOMAIN_NAME(String lookup)
	{
		try
		{
			if(lookup.endsWith("."))
				lookup = lookup.substring(0, lookup.length()-1);
			
			arr = lookup.split("\\.");
			
			if(arr == null || arr.length < 2)
			{				
				return false;
			}
			
			TLD = arr[arr.length-1].toLowerCase().trim();
			DOMAIN_NAME = arr[arr.length-2].toLowerCase().trim() + "." + arr[arr.length-1].toLowerCase().trim();
			
			return true;
		}
		
		catch(Exception e)
		{
			driver.eop(myClassName, "set_TLD_and_DOMAIN_NAME", e);
		}
		
		return false;
		
	}
	
	public boolean whois(String whois_iana_org_address, int port_to_whois, String lookup)
	{
		try
		{
			
			//first check if we already have the full contents
			if(this.tree_whois_lookup.containsKey(lookup.toLowerCase().trim()))
			{
				this.tree_whois_lookup.get(lookup.toLowerCase().trim()).print_whois("\n");
				return true;
			}
			
			if(lookup.equals("-"))
				return false;
			
			
			
			//get the TLD whois first
			set_TLD_and_DOMAIN_NAME(lookup);
			
			//set TLD REGISTRAR SERVER
			//this.TLD_WHOIS_REGISTRAR = this.derive_TLD_REGISTRAR_from_IANA(whois_iana_org_address, port_to_whois, lookup);
			
			//set whois registrar server
			this.REGISTRAR_WHOIS_SERVER = this.derive_REGISTRAR_WHOIS_SERVER(whois_iana_org_address, port_to_whois, lookup);
			
			if(tree_whois_lookup.containsKey(this.DOMAIN_NAME.toLowerCase().trim()))
			{
				this.REGISTRAR_WHOIS_SERVER = this.TLD_WHOIS_REGISTRAR;				
			}
			
			if(REGISTRAR_WHOIS_SERVER == null || REGISTRAR_WHOIS_SERVER.trim().equals(""))
			{
				sop("\nPunt!!! Whois registrar could not be located for [" + lookup + "]");
				return false;
			}
			
			//omit domains that end in .cc for now... the registrars take way too long to respond... it's holding the entire retrieval routine up
			if(lookup.toLowerCase().trim().endsWith(".cc") || REGISTRAR_WHOIS_SERVER.toLowerCase().endsWith(".cc"))
				return false;
			
			if(lookup.toLowerCase().trim().endsWith(".ir") || REGISTRAR_WHOIS_SERVER.toLowerCase().endsWith(".ir"))
				return false;
			
			if(lookup.toLowerCase().trim().endsWith(".ng") || REGISTRAR_WHOIS_SERVER.toLowerCase().endsWith(".ng"))
				return false;
			
			//Connect out
			sop("\nAttempting to connect to [" + REGISTRAR_WHOIS_SERVER + " : " + port_to_whois + "] to derive whois registration data for --> " +  DOMAIN_NAME);
			//Socket skt = new Socket(REGISTRAR_WHOIS_SERVER, 43);
			Socket skt = new Socket();
			skt.connect(new InetSocketAddress(REGISTRAR_WHOIS_SERVER, PORT_WHOIS), SOCKET_TIMEOUT);
			skt.setSoTimeout(SOCKET_TIMEOUT);
			
			sop("Connection to [" + REGISTRAR_WHOIS_SERVER + "] registrar established. Parsing data now...");
			
			//note: return here to parse full contents... however for now, we're just looking for the registrar whois address
			BufferedReader brIn = new BufferedReader(new InputStreamReader(skt.getInputStream()));
			PrintWriter pwOut = new PrintWriter(new OutputStreamWriter(skt.getOutputStream()), true);
			
			//submit request
			pwOut.println(DOMAIN_NAME);
			
			//listen to input
			String line = "";
			
			Log log = new Log("whois",  DOMAIN_NAME, 250, 999999999);
			
			while((line = brIn.readLine()) != null)
			{
				line = line.replaceAll("\t", " ").trim();
												
				if(line.equals(""))
					continue;
				
				parse_whois_server(line);
				
				//log
				log.log(line);
								
			}
			
			//determine if found whois registrar server
			if(this.REGISTRAR_WHOIS_SERVER != null && !this.REGISTRAR_WHOIS_SERVER.equals(""))
				tree_whois_registrar_server.put(DOMAIN_NAME, this);
			
			try	{	brIn.close();	}	catch(Exception e){}
			try	{	pwOut.close();	}	catch(Exception e){}
			try	{	skt.close();	}	catch(Exception e){}
			
			sop("Connection with Domain Name registrar [" + REGISTRAR_WHOIS_SERVER + "] complete\n");

			
			//
			// store!
			//
			if(STORE_WHOIS && DOMAIN_NAME != null && this.creation_date != null && this.registrar_registration_expiration_date != null && this.registrant_name != null && this.registrant_email != null && this.admin_name != null && this.admin_email != null && this.tech_name != null && this.tech_email != null)
			{
				if(this.DOMAIN_NAME != null && !this.DOMAIN_NAME.trim().equals("") && !this.tree_whois_lookup.containsKey(this.DOMAIN_NAME.toLowerCase().trim()))
					this.tree_whois_lookup.put(this.DOMAIN_NAME.toLowerCase().trim(), this);
				
				//e.g. for .biz
				if(this.REGISTRAR_WHOIS_SERVER == null || this.REGISTRAR_WHOIS_SERVER.trim().equals(""))
				{
					REGISTRAR_WHOIS_SERVER = this.TLD_WHOIS_REGISTRAR;
					this.registrar_whois_server = this.REGISTRAR_WHOIS_SERVER;
				}
				
				//
				//perform nslookup
				//
				node_nslookup = Node_Nslookup.resolve(DOMAIN_NAME);
				
				//
				//geo
				//
				if(Node_GeoIP.geo_requests_per_hour_count < Node_GeoIP.max_geo_requests_per_hour)
				{					
					node_geo = Node_GeoIP.resolve(DOMAIN_NAME, false);	
					
					//analyze the IP, if it appears to be IPv6, then try to submit a new request for a specific IP address if we have it
					if(node_geo != null && node_geo.ip != null && node_geo.ip.contains(":") && this.name_server_IP1 != null && !this.name_server_IP1.trim().equals(""))
					{
						//try again with this new ip, but not with the potential ipv6
						node_geo = Node_GeoIP.resolve(this.name_server_IP1, false);
					}
				}
				
				//
				//LOG!!!!
				//
				if(log_excalibur_whois_data_line == null)
				{
					log_excalibur_whois_data_line = new Log("excalibur_whois_data_file",  "excalibur_whois_data_file", 250, 999999999);
					log_excalibur_whois_data_line.log(this.get_whois_line_file_header("\t"));
				}
				
				//log based on if we have geo and nslookup data
				if(this.node_geo != null && this.node_nslookup != null)
					log_excalibur_whois_data_line.log(this.get_whois_data_line("\t", this.node_nslookup.get_details(true, ":", "\t"), this.node_geo.get_details(true, ":", "\t")));
				else if(this.node_geo != null)
					log_excalibur_whois_data_line.log(this.get_whois_data_line("\t", Node_Nslookup.BLANK_ROW, this.node_geo.get_details(true, ":", "\t")));
				else if(this.node_nslookup != null)
					log_excalibur_whois_data_line.log(this.get_whois_data_line("\t", this.node_nslookup.get_details(true, ":", "\t"), Node_GeoIP.BLANK_ROW));
				
				
				
				
			}
			
			
			return true;
		}
		catch(SocketTimeoutException ste)
		{
			driver.directive("\nPUNT! Distant end took too long beyone my current socket timeout of [" + this.SOCKET_TIMEOUT/1000 + "] seconds. I'm rejecting this resolution for [" + DOMAIN_NAME + "]");
		}
		catch(UnknownHostException uhe)
		{
			driver.directive("\n* * -- * * ERROR! I am unable to establish an outbound socket connection. Please ensure I am connected to the internet and not being blocked by firewall..");
		}
		catch(ConnectException ce)
		{
			driver.directive("\n* ERROR! I am unable to establish an outbound socket connection. Please ensure I am connected to the internet and not being blocked by firewall.. Error Code 2.");
		}
		catch(SocketException se)
		{
			driver.directive("\n* * * ERROR! I am unable to establish an outbound socket connection. Connection likely succeeded, but distant end refused to allow me to connect.  Perhaps we exceeded a connection limit?");
		}		
		catch(Exception e)
		{
			driver.eop(myClassName, "whois", e);
		}
		
		return false;
	}
	
	
	public String ping(String address, int ping_count, boolean print_output)
	{
		try
		{
			if(driver.isWindows)
			{
				ping_command = "ping -n " + ping_count + " "; 
				
			}
			else if(driver.isLinux)
			{
				ping_command = "ping -c " + ping_count + " "; 
			}
				
			Process proc = Runtime.getRuntime().exec(ping_command + address);	
			String line = "";
						
			BufferedReader brIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
			while((line = brIn.readLine()) != null)
			{
				try
				{
					line = line.trim();
					
					if(print_output)
						driver.directive(line);
					
					if(line.equals(""))
						continue;
					
					//determine if we have an ip address
					if(line.contains("("))
					{
						line = line.substring(line.indexOf("(")+1, line.lastIndexOf(")"));
						break;
					}
					
					else if(line.contains("["))
					{
						line = line.substring(line.indexOf("[")+1, line.lastIndexOf("]"));
						break;
					}
														
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "ping", e, -1);
					continue;
				}
				
			}	
				
				
			return line;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ping", e);
		}
		
		return null;
	}
	
	/**
	 * First process. Contact whois.iana.org:43 and request registrar server for TLD (e.g. COM, NET, ORG, etc)
	 * @param whois_iana_org_address
	 * @param port_to_whois
	 * @param lookup
	 * @return
	 */
	public String derive_TLD_REGISTRAR_from_IANA(String whois_iana_org_address, int port_to_whois, String lookup)
	{
		try
		{
			if(lookup == null || lookup.trim().equals(""))
				return null;
			
			lookup = lookup.replaceAll("\t", " ");
			
			//
			//Normalize
			//
			
			LOOKUP_ORIGINAL = lookup;
			
			lookup = lookup.trim();
			
			if(lookup.endsWith("."))
				lookup = lookup.substring(0, lookup.length()-1);
			
			arr = lookup.split("\\.");
			
			if(arr == null || arr.length < 1)
			{
				driver.directive("PUNT! Unable to derive TLD Domain from [" + LOOKUP_ORIGINAL + "]");
				return null;
			}
			
			lookup = arr[arr.length-1].toLowerCase().trim();
			
			TLD = lookup;
			
			//
			//check the cache first
			//
			if(cache_IANA_TLD.containsKey(lookup))
			{
				return cache_IANA_TLD.get(lookup).TLD_WHOIS_REGISTRAR;
			}
			
			//
			//otw, attempt to perform the retrieval
			//
			
			
			//Connect out
			if(!surpress_output)
				sop("\nAttempting to connect to [" + whois_iana_org_address + " : " + port_to_whois + "] to derive whois registrar ---> " +  lookup);
			
			Socket skt = new Socket(whois_iana_org_address, 43);
			
			if(!surpress_output)
				sop("Connection to IANA established! Parsing data now for [" + lookup + "]...");
			
			//note: return here to parse full contents... however for now, we're just looking for the registrar whois address
			BufferedReader brIn = new BufferedReader(new InputStreamReader(skt.getInputStream()));
			PrintWriter pwOut = new PrintWriter(new OutputStreamWriter(skt.getOutputStream()), true);
			
			//submit request
			pwOut.println(lookup);
			
			//listen to input
			String line = "";
			
			Log log = new Log("tld_registrars",  lookup, 250, 999999999);
			
			while((line = brIn.readLine()) != null)
			{
				line = line.replaceAll("\t", " ").trim();
												
				if(line.equals(""))
					continue;
				
				if(line.toLowerCase().startsWith("whois:"))
				{
					TLD_WHOIS_REGISTRAR_FULL_LINE = line.trim();
					TLD_WHOIS_REGISTRAR = line.substring(6).trim();		
					
					//found what we're looking for, store in the cache
					cache_IANA_TLD.put(lookup,  this);
					
					//store this in the large list
					if(log_tld_all == null)
						log_tld_all = new Log("tld_registrars",  "TLD_ALL", 250, 999999999);
					
					log_tld_all.log(lookup + "\t" + TLD_WHOIS_REGISTRAR);
				}
				
				if(line.toLowerCase().startsWith("registrar whois server:"))
				{
					TLD_WHOIS_REGISTRAR_FULL_LINE = line.trim();
					TLD_WHOIS_REGISTRAR = line.substring(23).trim();	
					
					this.REGISTRAR_WHOIS_SERVER = TLD_WHOIS_REGISTRAR;
					
					//found what we're looking for, store in the cache
					cache_IANA_TLD.put(lookup,  this);
					
					//store this in the large list
					if(log_tld_all == null)
						log_tld_all = new Log("tld_registrars",  "TLD_ALL", 250, 999999999);
					
					log_tld_all.log(lookup + "\t" + TLD_WHOIS_REGISTRAR);
				}
				
				//log
				log.log(line);
								
			}
			
			
			
			try	{	brIn.close();	}	catch(Exception e){}
			try	{	pwOut.close();	}	catch(Exception e){}
			try	{	skt.close();	}	catch(Exception e){}
			
			if(!surpress_output)
				sop("Connection with IANA complete for [" + lookup + "]");
			
			return TLD_WHOIS_REGISTRAR;
		}
		catch(UnknownHostException uhe)
		{
			driver.directive("\n* * -- * * ERROR! I am unable to establish an outbound socket connection. Please ensure I am connected to the internet and not being blocked by firewall..");
		}
		catch(ConnectException ce)
		{
			driver.directive("\nERROR! I am unable to establish an outbound socket connection. Please ensure I am connected to the internet and not being blocked by firewall.. Error Code 1.");
		}
		catch(SocketException se)
		{
			driver.directive("\n* ERROR! I am unable to establish an outbound socket connection. Connection likely succeeded, but distant end refused to allow me to connect.  Perhaps we exceeded a connection limit?");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "derive_TLD_REGISTRAR_from_IANA", e);
		}
		
		return null;
	}
	
	
	
	/**
	 * SECOND PROCESS: after finding TLD whois (e.g whois.verisign-grs.com), find the specific whois registrar server for a domain e.g. google.com. we're expecting whois.markmonitor.com
	 * @param whois_iana_org_address
	 * @param port_to_whois
	 * @param lookup
	 * @return
	 */
	public String derive_REGISTRAR_WHOIS_SERVER(String whois_iana_org_address, int port_to_whois, String lookup)
	{
		try
		{
			if(lookup == null || lookup.trim().equals(""))
				return null;
			
			lookup = lookup.replaceAll("\t", " ").trim();
			
			//
			//Normalize
			//
			
			LOOKUP_ORIGINAL = lookup;
			
			lookup = lookup.trim();
			
			if(lookup.endsWith("."))
				lookup = lookup.substring(0, lookup.length()-1);
			
			arr = lookup.split("\\.");
			
			if(arr == null || arr.length < 2)
			{
				driver.directive("PUNT!! Unable to derive Whois Registrar Server from [" + LOOKUP_ORIGINAL + "]. Full domain name is not accurate...");
				return null;
			}
			
			
			
			TLD = arr[arr.length-1].toLowerCase().trim();
			DOMAIN_NAME = arr[arr.length-2].toLowerCase().trim() + "." + arr[arr.length-1].toLowerCase().trim();
			
			
			lookup = DOMAIN_NAME;
									
						
			//
			//check the cache first if we know TLD whois server
			//
			if(cache_IANA_TLD.containsKey(TLD))
				TLD_WHOIS_REGISTRAR = cache_IANA_TLD.get(TLD).TLD_WHOIS_REGISTRAR;
			else
			{
				TLD_WHOIS_REGISTRAR = this.derive_TLD_REGISTRAR_from_IANA(whois_iana_org_address, port_to_whois, TLD);
				
				//check if we have the initial tld registrar to query
				if(TLD_WHOIS_REGISTRAR == null || TLD_WHOIS_REGISTRAR.trim().equals(""))
					return null;
			}
			
			//
			//now, check if we already have the registrar whois server
			//
			if(tree_whois_lookup.containsKey(DOMAIN_NAME))
				return tree_whois_lookup.get(DOMAIN_NAME).REGISTRAR_WHOIS_SERVER;
			else if(tree_whois_registrar_server.containsKey(DOMAIN_NAME))
				return tree_whois_registrar_server.get(DOMAIN_NAME).REGISTRAR_WHOIS_SERVER;
			
			
			//
			//otw, connect out to query for the registrar whois server
			//
			
			//Connect out
			sop("\nAttempting to connect to [" + TLD_WHOIS_REGISTRAR + " : " + port_to_whois + "] to derive whois registrar --> " +  DOMAIN_NAME);
			Socket skt = new Socket(TLD_WHOIS_REGISTRAR, 43);
			
			sop("Connection to TLD registrar established. Parsing data now for [" + DOMAIN_NAME + "]...");
			
			//note: return here to parse full contents... however for now, we're just looking for the registrar whois address
			BufferedReader brIn = new BufferedReader(new InputStreamReader(skt.getInputStream()));
			PrintWriter pwOut = new PrintWriter(new OutputStreamWriter(skt.getOutputStream()), true);
			
			//submit request
			pwOut.println(DOMAIN_NAME);
			
			//listen to input
			String line = "";
			
			Log log = new Log("whois_registrars",  DOMAIN_NAME, 250, 999999999);
			
			while((line = brIn.readLine()) != null)
			{
				line = line.replaceAll("\t", " ").trim();
												
				if(line.equals(""))
					continue;
				
				parse_whois_server(line);
				
				//log
				log.log(line);
								
			}
			
			//determine if found whois registrar server
			if(this.REGISTRAR_WHOIS_SERVER != null && !this.REGISTRAR_WHOIS_SERVER.equals(""))
				tree_whois_registrar_server.put(DOMAIN_NAME, this);
			
			try	{	brIn.close();	}	catch(Exception e){}
			try	{	pwOut.close();	}	catch(Exception e){}
			try	{	skt.close();	}	catch(Exception e){}
			
			sop("Connection with TLD registrar complete for [" + DOMAIN_NAME + "]");
			
			
			/**solomon sonya*/
			//determine if we believe we have full details from the request
			//at times, we may get full details from the whois registrar (one level below TLD registrar)
			//whereas the actual whois registrar server (one level below whois registrar server)
			//may choose to restrict this data e.g. 
			//research loan.info
			//whois.afilias.net : 43 has more details than the registrar server whois.godaddy.com
			//so in these cases, keep the information from the whois registrar
			
			if(STORE_WHOIS && DOMAIN_NAME != null && this.creation_date != null && this.registrar_registration_expiration_date != null && this.registrant_name != null && this.registrant_email != null && this.admin_name != null && this.admin_email != null && this.tech_name != null && this.tech_email != null)
			{
				if(this.DOMAIN_NAME != null && !this.DOMAIN_NAME.trim().equals("") && !this.tree_whois_lookup.containsKey(this.DOMAIN_NAME.toLowerCase().trim()))
					this.tree_whois_lookup.put(this.DOMAIN_NAME.toLowerCase().trim(), this);
			}
			
			
			
			/*driver.directive("	domain_name	-->" + 	domain_name	);
			driver.directive("	registry_domain_id	-->" + 	registry_domain_id	);
			driver.directive("	registrar_whois_server	-->" + 	registrar_whois_server	);
			driver.directive("	registrar_url	-->" + 	registrar_url	);
			driver.directive("	updated_date	-->" + 	updated_date	);
			driver.directive("	creation_date	-->" + 	creation_date	);
			driver.directive("	registry_expiry_date	-->" + 	registry_expiry_date	);
			driver.directive("	registrar	-->" + 	registrar	);
			driver.directive("	registrar_iana_id	-->" + 	registrar_iana_id	);
			driver.directive("	registrar_abuse_contact_email	-->" + 	registrar_abuse_contact_email	);
			driver.directive("	registrar_abuse_contact_phone	-->" + 	registrar_abuse_contact_phone	);
			driver.directive("	domain_status1	-->" + 	domain_status1	);
			driver.directive("	domain_status2	-->" + 	domain_status2	);
			driver.directive("	domain_status3	-->" + 	domain_status3	);
			driver.directive("	domain_status4	-->" + 	domain_status4	);
			driver.directive("	domain_status5	-->" + 	domain_status5	);
			driver.directive("	domain_status6	-->" + 	domain_status6	);
			driver.directive("	domain_status7	-->" + 	domain_status7	);
			driver.directive("	domain_status8	-->" + 	domain_status8	);
			driver.directive("	domain_status9	-->" + 	domain_status9	);
			driver.directive("	domain_status10	-->" + 	domain_status10	);
			driver.directive("	name_server1	-->" + 	name_server_NAME1	);
			driver.directive("	name_server2	-->" + 	name_server_NAME2	);
			driver.directive("	name_server3	-->" + 	name_server_NAME3	);
			driver.directive("	name_server4	-->" + 	name_server_NAME4	);
			driver.directive("	name_server5	-->" + 	name_server_NAME5	);
			driver.directive("	name_server6	-->" + 	name_server_NAME6	);
			driver.directive("	name_server7	-->" + 	name_server_NAME7	);
			driver.directive("	name_server8	-->" + 	name_server_NAME8	);
			driver.directive("	name_server9	-->" + 	name_server_NAME9	);
			driver.directive("	name_server10	-->" + 	name_server_NAME10	);
			driver.directive("	name_server11	-->" + 	name_server_NAME11	);
			driver.directive("	name_server12	-->" + 	name_server_NAME12	);
			driver.directive("	name_server13	-->" + 	name_server_NAME13	);
			driver.directive("	name_server14	-->" + 	name_server_NAME14	);
			driver.directive("	name_server15	-->" + 	name_server_NAME15	);
			driver.directive("	name_server6	-->" + 	name_server_NAME16	);
			driver.directive("	name_server7	-->" + 	name_server_NAME17	);
			driver.directive("	name_server8	-->" + 	name_server_NAME18	);
			driver.directive("	name_server9	-->" + 	name_server_NAME19	);
			driver.directive("	name_server10	-->" + 	name_server_NAME20	);
			driver.directive("	name_server1	-->" + 	name_server_IP1	);
			driver.directive("	name_server2	-->" + 	name_server_IP2	);
			driver.directive("	name_server3	-->" + 	name_server_IP3	);
			driver.directive("	name_server4	-->" + 	name_server_IP4	);
			driver.directive("	name_server5	-->" + 	name_server_IP5	);
			driver.directive("	name_server6	-->" + 	name_server_IP6	);
			driver.directive("	name_server7	-->" + 	name_server_IP7	);
			driver.directive("	name_server8	-->" + 	name_server_IP8	);
			driver.directive("	name_server9	-->" + 	name_server_IP9	);
			driver.directive("	name_server10	-->" + 	name_server_IP10	);
			driver.directive("	name_server11	-->" + 	name_server_IP11	);
			driver.directive("	name_server12	-->" + 	name_server_IP12	);
			driver.directive("	name_server13	-->" + 	name_server_IP13	);
			driver.directive("	name_server14	-->" + 	name_server_IP14	);
			driver.directive("	name_server15	-->" + 	name_server_IP15	);
			driver.directive("	name_server6	-->" + 	name_server_IP16	);
			driver.directive("	name_server7	-->" + 	name_server_IP17	);
			driver.directive("	name_server8	-->" + 	name_server_IP18	);
			driver.directive("	name_server9	-->" + 	name_server_IP19	);
			driver.directive("	name_server10	-->" + 	name_server_IP20	);
			driver.directive("	dnssec	-->" + 	dnssec	);*/

			
			
			return this.REGISTRAR_WHOIS_SERVER;
		}
		catch(UnknownHostException uhe)
		{
			driver.directive("\n* * -- * * ERROR! I am unable to establish an outbound socket connection. Please ensure I am connected to the internet and not being blocked by firewall..");
		}
		catch(ConnectException ce)
		{
			driver.directive("\nERROR!!! I am unable to establish an outbound socket connection. Please ensure I am connected to the internet and not being blocked by firewall.. Error Code 2.");
		}
		catch(SocketException se)
		{
			driver.directive("\n* * ERROR! I am unable to establish an outbound socket connection. Connection likely succeeded, but distant end refused to allow me to connect.  Perhaps we exceeded a connection limit?");
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "derive_REGISTRAR_WHOIS_SERVER", e);
			//e.printStackTrace(System.out);
		}
		
		return null;
	}
	
	public boolean print_whois(String end_of_line_delimiter)
	{
		try
		{
			driver.directivesp("Domain Name: " + domain_name + end_of_line_delimiter);
			driver.directivesp("Registry Domain ID: " + registry_domain_id + end_of_line_delimiter);
			driver.directivesp("Registrar Whois Server: " + registrar_whois_server + end_of_line_delimiter);
			driver.directivesp("Registrar Url: " + registrar_url + end_of_line_delimiter);
			driver.directivesp("Updated Date: " + updated_date + end_of_line_delimiter);
			driver.directivesp("Creation Date: " + creation_date + end_of_line_delimiter);
			driver.directivesp("Registrar Registration Expiration Date: " + registrar_registration_expiration_date + end_of_line_delimiter);
			driver.directivesp("Registrar: " + registrar + end_of_line_delimiter);
			driver.directivesp("Registrar Iana ID: " + registrar_iana_id + end_of_line_delimiter);
			driver.directivesp("Registrar Abuse Contact Email: " + registrar_abuse_contact_email + end_of_line_delimiter);
			driver.directivesp("Registrar Abuse Contact Phone: " + registrar_abuse_contact_phone + end_of_line_delimiter);

			if(registrar_abuse_contact_ext != null && !registrar_abuse_contact_ext.trim().equals(""))
			driver.directivesp("registrar_abuse_contact_ext: " + registrar_abuse_contact_ext + end_of_line_delimiter);

			driver.directivesp(get_domain_status_list(end_of_line_delimiter, false));

			driver.directivesp("Registry Registrant ID: " + registry_registrant_id + end_of_line_delimiter);
			driver.directivesp("Registrant Name: " + registrant_name + end_of_line_delimiter);
			driver.directivesp("Registrant Organization: " + registrant_organization + end_of_line_delimiter);
			driver.directivesp("Registrant Street: " + registrant_street + end_of_line_delimiter);
			driver.directivesp("Registrant City: " + registrant_city + end_of_line_delimiter);
			driver.directivesp("Registrant State Province: " + registrant_state_province + end_of_line_delimiter);
			driver.directivesp("Registrant Postal Code: " + registrant_postal_code + end_of_line_delimiter);
			driver.directivesp("Registrant Country: " + registrant_country + end_of_line_delimiter);
			driver.directivesp("Registrant Phone: " + registrant_phone + end_of_line_delimiter);
			driver.directivesp("Registrant Phone Ext: " + registrant_phone_ext + end_of_line_delimiter);
			driver.directivesp("Registrant Fax: " + registrant_fax + end_of_line_delimiter);
			driver.directivesp("Registrant Fax Ext: " + registrant_fax_ext + end_of_line_delimiter);
			driver.directivesp("Registrant Email: " + registrant_email + end_of_line_delimiter);
			driver.directivesp("Registry Admin Id: " + registry_admin_id + end_of_line_delimiter);
			driver.directivesp("Admin Name: " + admin_name + end_of_line_delimiter);
			driver.directivesp("Admin Organization: " + admin_organization + end_of_line_delimiter);
			driver.directivesp("Admin Street: " + admin_street + end_of_line_delimiter);
			driver.directivesp("Admin City: " + admin_city + end_of_line_delimiter);
			driver.directivesp("Admin State Province: " + admin_state_province + end_of_line_delimiter);
			driver.directivesp("Admin Postal Code: " + admin_postal_code + end_of_line_delimiter);
			driver.directivesp("Admin Country: " + admin_country + end_of_line_delimiter);
			driver.directivesp("Admin Phone: " + admin_phone + end_of_line_delimiter);
			driver.directivesp("Admin Phone Ext: " + admin_phone_ext + end_of_line_delimiter);
			driver.directivesp("Admin Fax: " + admin_fax + end_of_line_delimiter);
			driver.directivesp("Admin Fax Ext: " + admin_fax_ext + end_of_line_delimiter);
			driver.directivesp("Admin Email: " + admin_email + end_of_line_delimiter);
			driver.directivesp("Registry Tech ID: " + registry_tech_id + end_of_line_delimiter);
			driver.directivesp("Tech Name: " + tech_name + end_of_line_delimiter);
			driver.directivesp("Tech Organization: " + tech_organization + end_of_line_delimiter);
			driver.directivesp("Tech Street: " + tech_street + end_of_line_delimiter);
			driver.directivesp("Tech City: " + tech_city + end_of_line_delimiter);
			driver.directivesp("Tech State Province: " + tech_state_province + end_of_line_delimiter);
			driver.directivesp("Tech Postal Code: " + tech_postal_code + end_of_line_delimiter);
			driver.directivesp("Tech Country: " + tech_country + end_of_line_delimiter);
			driver.directivesp("Tech Phone: " + tech_phone + end_of_line_delimiter);
			driver.directivesp("Tech Phone Ext: " + tech_phone_ext + end_of_line_delimiter);
			driver.directivesp("Tech Fax: " + tech_fax + end_of_line_delimiter);
			driver.directivesp("Tech Fax Ext: " + tech_fax_ext + end_of_line_delimiter);
			driver.directivesp("Tech Email: " + tech_email + end_of_line_delimiter);

			driver.directivesp(this.get_name_server_list(end_of_line_delimiter, false));
			driver.directivesp(this.get_name_server_IP_list(end_of_line_delimiter, false));

			driver.directivesp("DNSSEC: " + dnssec + end_of_line_delimiter);
			
			
			if(whois_server != null && !whois_server.trim().equals(""))
				driver.directivesp("Whois Server: " + whois_server + end_of_line_delimiter);
			
			if(referral_url != null && !referral_url.trim().equals(""))
				driver.directivesp("Referral URL: " + referral_url + end_of_line_delimiter);

			if(billing_id != null && !billing_id.trim().equals(""))
			{
			driver.directivesp("billing_id: " + billing_id + end_of_line_delimiter);
			driver.directivesp("billing_name: " + billing_name + end_of_line_delimiter);
			driver.directivesp("billing_organization: " + billing_organization + end_of_line_delimiter);
			driver.directivesp("billing_street: " + billing_street + end_of_line_delimiter);
			driver.directivesp("billing_city: " + billing_city + end_of_line_delimiter);
			driver.directivesp("billing_state_province: " + billing_state_province + end_of_line_delimiter);
			driver.directivesp("billing_postal_code: " + billing_postal_code + end_of_line_delimiter);
			driver.directivesp("billing_country: " + billing_country + end_of_line_delimiter);
			driver.directivesp("billing_phone: " + billing_phone + end_of_line_delimiter);
			driver.directivesp("billing_phone_ext: " + billing_phone_ext + end_of_line_delimiter);
			driver.directivesp("billing_fax: " + billing_fax + end_of_line_delimiter);
			driver.directivesp("billing_fax_ext: " + billing_fax_ext + end_of_line_delimiter);
			}


			driver.directivesp("first lookup date: " + first_lookup_date + end_of_line_delimiter);
			driver.directivesp("last lookup date: " + last_lookup_date + end_of_line_delimiter);

			if(this.node_nslookup != null)
				driver.directive("\n" + this.node_nslookup.get_details(true, ":", "\n"));
			
			if(this.node_geo != null)
				driver.directive("\n" + this.node_geo.get_details(true, ":", "\n"));
			

			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_whois", e);
		}
		
		return false;
	}
	
	
	
	public String get_name_server_list(String end_of_line_delimiter, boolean include_html_headers)
	{
		try
		{
			this.name_server_concat = "";
			
			if(this.name_server_NAME1 != null && !this.name_server_NAME1.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME1 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME1 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME2 != null && !this.name_server_NAME2.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME2 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME2 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME3 != null && !this.name_server_NAME3.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME3 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME3 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME4 != null && !this.name_server_NAME4.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME4 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME4 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME5 != null && !this.name_server_NAME5.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME5 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME5 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME6 != null && !this.name_server_NAME6.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME6 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME6 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME7 != null && !this.name_server_NAME7.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME7 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME7 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME8 != null && !this.name_server_NAME8.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME8 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME8 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME9 != null && !this.name_server_NAME9.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME9 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME9 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME10 != null && !this.name_server_NAME10.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME10 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME10 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME11 != null && !this.name_server_NAME11.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME11 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME11 + end_of_line_delimiter;			
			}
			
			if(this.name_server_NAME12 != null && !this.name_server_NAME12.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME12 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME12 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME13 != null && !this.name_server_NAME13.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME13 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME13 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME14 != null && !this.name_server_NAME14.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME14 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME14 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME15 != null && !this.name_server_NAME15.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME15 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME15 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME16 != null && !this.name_server_NAME16.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME16 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME16 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME17 != null && !this.name_server_NAME17.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME17 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME17 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME18 != null && !this.name_server_NAME18.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME18 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME18 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME19 != null && !this.name_server_NAME19.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME19 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME19 + end_of_line_delimiter;
			}
			
			if(this.name_server_NAME20 != null && !this.name_server_NAME20.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server:</b> " + name_server_NAME20 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server: " + name_server_NAME20 + end_of_line_delimiter;
			}
			
			return name_server_concat;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_name_server", e);
		}
		
		return "name server:" + this.name_server_NAME1;
	}
	
	public boolean write_excalibur_whois_log()
	{
		try
		{
			Log log = new Log("whois_excalibur",  DOMAIN_NAME, 250, 99999999);
			
			log.log("Domain Name: " + domain_name);
			log.log("Registry Domain ID: " + registry_domain_id);
			log.log("Registrar Whois Server: " + registrar_whois_server);
			log.log("Registrar Url: " + registrar_url);
			log.log("Updated Date: " + updated_date);
			log.log("Creation Date: " + creation_date);
			log.log("Registrar Registration Expiration Date: " + registrar_registration_expiration_date);
			log.log("Registrar: " + registrar);
			log.log("Registrar Iana ID: " + registrar_iana_id);
			log.log("Registrar Abuse Contact Email: " + registrar_abuse_contact_email);
			log.log("Registrar Abuse Contact Phone: " + registrar_abuse_contact_phone);

			if(registrar_abuse_contact_ext != null && !registrar_abuse_contact_ext.trim().equals(""))
			log.log("registrar_abuse_contact_ext: " + registrar_abuse_contact_ext);

			log.log(get_domain_status_list("\n", false));

			log.log("Registry Registrant ID: " + registry_registrant_id);
			log.log("Registrant Name: " + registrant_name);
			log.log("Registrant Organization: " + registrant_organization);
			log.log("Registrant Street: " + registrant_street);
			log.log("Registrant City: " + registrant_city);
			log.log("Registrant State Province: " + registrant_state_province);
			log.log("Registrant Postal Code: " + registrant_postal_code);
			log.log("Registrant Country: " + registrant_country);
			log.log("Registrant Phone: " + registrant_phone);
			log.log("Registrant Phone Ext: " + registrant_phone_ext);
			log.log("Registrant Fax: " + registrant_fax);
			log.log("Registrant Fax Ext: " + registrant_fax_ext);
			log.log("Registrant Email: " + registrant_email);
			log.log("Registry Admin Id: " + registry_admin_id);
			log.log("Admin Name: " + admin_name);
			log.log("Admin Organization: " + admin_organization);
			log.log("Admin Street: " + admin_street);
			log.log("Admin City: " + admin_city);
			log.log("Admin State Province: " + admin_state_province);
			log.log("Admin Postal Code: " + admin_postal_code);
			log.log("Admin Country: " + admin_country);
			log.log("Admin Phone: " + admin_phone);
			log.log("Admin Phone Ext: " + admin_phone_ext);
			log.log("Admin Fax: " + admin_fax);
			log.log("Admin Fax Ext: " + admin_fax_ext);
			log.log("Admin Email: " + admin_email);
			log.log("Registry Tech ID: " + registry_tech_id);
			log.log("Tech Name: " + tech_name);
			log.log("Tech Organization: " + tech_organization);
			log.log("Tech Street: " + tech_street);
			log.log("Tech City: " + tech_city);
			log.log("Tech State Province: " + tech_state_province);
			log.log("Tech Postal Code: " + tech_postal_code);
			log.log("Tech Country: " + tech_country);
			log.log("Tech Phone: " + tech_phone);
			log.log("Tech Phone Ext: " + tech_phone_ext);
			log.log("Tech Fax: " + tech_fax);
			log.log("Tech Fax Ext: " + tech_fax_ext);
			log.log("Tech Email: " + tech_email);

			log.log(this.get_name_server_list("\n", false));
			log.log(this.get_name_server_IP_list("\n", false));

			log.log("DNSSEC: " + dnssec);
			
			
			if(whois_server != null && !whois_server.trim().equals(""))
				log.log("Whois Server: " + whois_server);
			
			if(referral_url != null && !referral_url.trim().equals(""))
				log.log("Referral URL: " + referral_url);

			if(billing_id != null && !billing_id.trim().equals(""))
			{
				log.log("billing_id: " + billing_id);
				log.log("billing_name: " + billing_name);
				log.log("billing_organization: " + billing_organization);
				log.log("billing_street: " + billing_street);
				log.log("billing_city: " + billing_city);
				log.log("billing_state_province: " + billing_state_province);
				log.log("billing_postal_code: " + billing_postal_code);
				log.log("billing_country: " + billing_country);
				log.log("billing_phone: " + billing_phone);
				log.log("billing_phone_ext: " + billing_phone_ext);
				log.log("billing_fax: " + billing_fax);
				log.log("billing_fax_ext: " + billing_fax_ext);
			}


			log.log("first lookup date: " + first_lookup_date);
			log.log("last lookup date: " + last_lookup_date);

			if(this.node_nslookup != null)
				log.log("\n" + this.node_nslookup.get_details(true, ":", "\n"));
			
			if(this.node_geo != null)
				log.log("\n" + this.node_geo.get_details(true, ":", "\n"));
			

			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "write_excalibur_whois", e);
		}
		
		return false;
	}
	
	public String get_domain_status_list(String end_of_line_delimiter, boolean include_html_headers)
	{
		try
		{
			this.domain_status_concat = "";
			
			if(this.domain_status1 != null && !this.domain_status1.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status1 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat + "Domain Status: " + domain_status1 + end_of_line_delimiter;
			}
			
			if(this.domain_status2 != null && !this.domain_status2.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status2 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status2 + end_of_line_delimiter;
			}
			
			if(this.domain_status3 != null && !this.domain_status3.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status3 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status3 + end_of_line_delimiter;
			}
			
			if(this.domain_status4 != null && !this.domain_status4.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status4 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status4 + end_of_line_delimiter;
			}
			
			if(this.domain_status5 != null && !this.domain_status5.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status5 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status5 + end_of_line_delimiter;
			}
			
			if(this.domain_status6 != null && !this.domain_status6.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status6 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status6 + end_of_line_delimiter;
			}
			
			if(this.domain_status7 != null && !this.domain_status7.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status7 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status7 + end_of_line_delimiter;
			}
			
			if(this.domain_status8 != null && !this.domain_status8.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status8 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status8 + end_of_line_delimiter;
			}
			
			if(this.domain_status9 != null && !this.domain_status9.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status9 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status9 + end_of_line_delimiter;
			}
			
			if(this.domain_status10 != null && !this.domain_status10.trim().equals(""))
			{
				if(include_html_headers)
					domain_status_concat = domain_status_concat + "<b>Domain Status:</b> " + domain_status10 + end_of_line_delimiter;
				else
					domain_status_concat = domain_status_concat +  "Domain Status: " + domain_status10 + end_of_line_delimiter;
			}
			
			
			
			return this.domain_status_concat;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_domain_status", e);
		}
		
		return "domain status:" + this.domain_status1;
	}
	
	/**
	 * called from print_whois
	 * @param end_of_line_delimiter
	 * @return
	 */
	public boolean print_whois(PrintWriter pwOut)
	{
		try
		{
			pwOut.println("<b>Domain Name:</b>   " + domain_name + "<br>");
			pwOut.println("<b>Registry Domain ID:</b>   " + registry_domain_id + "<br>");
			pwOut.println("<b>Registrar Whois Server:</b>   " + registrar_whois_server + "<br>");
			pwOut.println("<b>Registrar Url:</b>   " + registrar_url + "<br>");
			pwOut.println("<b>Updated Date:</b>   " + updated_date + "<br>");
			pwOut.println("<b>Creation Date:</b>   " + creation_date + "<br>");
			pwOut.println("<b>Registrar Registration Expiration Date:</b>   " + registrar_registration_expiration_date + "<br>");
			pwOut.println("<b>Registrar:</b>   " + registrar + "<br>");
			pwOut.println("<b>Registrar Iana ID:</b>   " + registrar_iana_id + "<br>");
			pwOut.println("<b>Registrar Abuse Contact Email:</b>   " + registrar_abuse_contact_email + "<br>");
			pwOut.println("<b>Registrar Abuse Contact Phone:</b>   " + registrar_abuse_contact_phone + "<br>");

			if(registrar_abuse_contact_ext != null && !registrar_abuse_contact_ext.trim().equals(""))
				pwOut.println("<b>registrar_abuse_contact_ext:</b>   " + registrar_abuse_contact_ext + "<br>");

			pwOut.println("<br>");
			
			pwOut.println(get_domain_status_list( "<br>", true));

			pwOut.println("<br>");
			pwOut.println("<b>Registry Registrant ID:</b>   " + registry_registrant_id + "<br>");
			pwOut.println("<b>Registrant Name:</b>   " + registrant_name + "<br>");
			pwOut.println("<b>Registrant Organization:</b>   " + registrant_organization + "<br>");
			pwOut.println("<b>Registrant Street:</b>   " + registrant_street + "<br>");
			pwOut.println("<b>Registrant City:</b>   " + registrant_city + "<br>");
			pwOut.println("<b>Registrant State Province:</b>   " + registrant_state_province + "<br>");
			pwOut.println("<b>Registrant Postal Code:</b>   " + registrant_postal_code + "<br>");
			pwOut.println("<b>Registrant Country:</b>   " + registrant_country + "<br>");
			pwOut.println("<b>Registrant Phone:</b>   " + registrant_phone + "<br>");
			pwOut.println("<b>Registrant Phone Ext:</b>   " + registrant_phone_ext + "<br>");
			pwOut.println("<b>Registrant Fax:</b>   " + registrant_fax + "<br>");
			pwOut.println("<b>Registrant Fax Ext:</b>   " + registrant_fax_ext + "<br>");
			pwOut.println("<b>Registrant Email:</b>   " + registrant_email + "<br>");
			
			
			pwOut.println("<br>");
			pwOut.println("<b>Registry Admin ID:</b>   " + registry_admin_id + "<br>");
			pwOut.println("<b>Admin Name:</b>   " + admin_name + "<br>");
			pwOut.println("<b>Admin Organization:</b>   " + admin_organization + "<br>");
			pwOut.println("<b>Admin Street:</b>   " + admin_street + "<br>");
			pwOut.println("<b>Admin City:</b>   " + admin_city + "<br>");
			pwOut.println("<b>Admin State Province:</b>   " + admin_state_province + "<br>");
			pwOut.println("<b>Admin Postal Code:</b>   " + admin_postal_code + "<br>");
			pwOut.println("<b>Admin Country:</b>   " + admin_country + "<br>");
			pwOut.println("<b>Admin Phone:</b>   " + admin_phone + "<br>");
			pwOut.println("<b>Admin Phone Ext:</b>   " + admin_phone_ext + "<br>");
			pwOut.println("<b>Admin Fax:</b>   " + admin_fax + "<br>");
			pwOut.println("<b>Admin Fax Ext:</b>   " + admin_fax_ext + "<br>");
			pwOut.println("<b>Admin Email:</b>   " + admin_email + "<br>");
			
			pwOut.println("<br>");
			pwOut.println("<b>Registry Tech ID:</b>   " + registry_tech_id + "<br>");
			pwOut.println("<b>Tech Name:</b>   " + tech_name + "<br>");
			pwOut.println("<b>Tech Organization:</b>   " + tech_organization + "<br>");
			pwOut.println("<b>Tech Street:</b>   " + tech_street + "<br>");
			pwOut.println("<b>Tech City:</b>   " + tech_city + "<br>");
			pwOut.println("<b>Tech State Province:</b>   " + tech_state_province + "<br>");
			pwOut.println("<b>Tech Postal Code:</b>   " + tech_postal_code + "<br>");
			pwOut.println("<b>Tech Country:</b>   " + tech_country + "<br>");
			pwOut.println("<b>Tech Phone:</b>   " + tech_phone + "<br>");
			pwOut.println("<b>Tech Phone Ext:</b>   " + tech_phone_ext + "<br>");
			pwOut.println("<b>Tech Fax:</b>   " + tech_fax + "<br>");
			pwOut.println("<b>Tech Fax Ext:</b>   " + tech_fax_ext + "<br>");
			pwOut.println("<b>Tech Email:</b>   " + tech_email + "<br>");

			pwOut.println("<br>");
			pwOut.println(this.get_name_server_list("<br>", true));
			
			pwOut.println("<br>");
			pwOut.println(this.get_name_server_IP_list("<br>", true));

			pwOut.println("<br>");
			pwOut.println("<b>DNSSEC:</b>   " + dnssec + "<br>");
			
			
			if(whois_server != null && !whois_server.trim().equals(""))
				pwOut.println("<b>Whois Server:</b>   " + whois_server + "<br>");
			
			if(referral_url != null && !referral_url.trim().equals(""))
				pwOut.println("<b>Referral URL:</b>   " + referral_url + "<br>");

			if(billing_id != null && !billing_id.trim().equals(""))
			{
				pwOut.println("<br>");
				pwOut.println("<b>billing_id:</b>   " + billing_id + "<br>");
				pwOut.println("<b>billing_name:</b>   " + billing_name + "<br>");
				pwOut.println("<b>billing_organization:</b>   " + billing_organization + "<br>");
				pwOut.println("<b>billing_street:</b>   " + billing_street + "<br>");
				pwOut.println("<b>billing_city:</b>   " + billing_city + "<br>");
				pwOut.println("<b>billing_state_province:</b>   " + billing_state_province + "<br>");
				pwOut.println("<b>billing_postal_code:</b>   " + billing_postal_code + "<br>");
				pwOut.println("<b>billing_country:</b>   " + billing_country + "<br>");
				pwOut.println("<b>billing_phone:</b>   " + billing_phone + "<br>");
				pwOut.println("<b>billing_phone_ext:</b>   " + billing_phone_ext + "<br>");
				pwOut.println("<b>billing_fax:</b>   " + billing_fax + "<br>");
				pwOut.println("<b>billing_fax_ext:</b>   " + billing_fax_ext + "<br>");
			}

			pwOut.println("<br>");
			pwOut.println("first lookup date:   " + first_lookup_date + "<br>");
			pwOut.println("last lookup date:   " + last_lookup_date + "<br>");

			

			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_whois_map_data", e);
		}
		
		return false;
	}
	
	public String get_name_server_IP_list(String end_of_line_delimiter, boolean include_html_headers)
	{
		try
		{
			this.name_server_concat = "";
			
			if(this.name_server_IP1 != null && !this.name_server_IP1.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP1 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP1 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP2 != null && !this.name_server_IP2.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP2 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP2 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP3 != null && !this.name_server_IP3.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP3 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP3 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP4 != null && !this.name_server_IP4.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP4 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP4 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP5 != null && !this.name_server_IP5.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP5 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP5 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP6 != null && !this.name_server_IP6.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP6 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP6 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP7 != null && !this.name_server_IP7.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP7 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP7 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP8 != null && !this.name_server_IP8.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP8 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP8 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP9 != null && !this.name_server_IP9.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP9 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP9 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP10 != null && !this.name_server_IP10.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP10 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP10 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP11 != null && !this.name_server_IP11.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP11 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP11 + end_of_line_delimiter;			
			}
			
			if(this.name_server_IP12 != null && !this.name_server_IP12.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP12 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP12 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP13 != null && !this.name_server_IP13.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP13 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP13 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP14 != null && !this.name_server_IP14.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP14 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP14 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP15 != null && !this.name_server_IP15.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP15 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP15 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP16 != null && !this.name_server_IP16.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP16 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP16 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP17 != null && !this.name_server_IP17.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP17 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP17 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP18 != null && !this.name_server_IP18.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP18 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP18 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP19 != null && !this.name_server_IP19.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP19 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP19 + end_of_line_delimiter;
			}
			
			if(this.name_server_IP20 != null && !this.name_server_IP20.trim().equals(""))
			{
				if(include_html_headers)
					name_server_concat = name_server_concat + "<b>Name Server IP:</b> " + name_server_IP20 + end_of_line_delimiter;
				else
					name_server_concat = name_server_concat + "Name Server IP: " + name_server_IP20 + end_of_line_delimiter;
			}
			
			return name_server_concat;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_name_server_IP_list", e);
		}
		
		return "name server ip:" + this.name_server_IP1;
	}
	
	public boolean parse_whois_server(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			//driver.directive(line);
			
			if(line.toLowerCase().startsWith("whois:"))
			{
				TLD_WHOIS_REGISTRAR_FULL_LINE = line.trim();
				TLD_WHOIS_REGISTRAR = line.substring(6).trim();		
				
				//found what we're looking for, store in the cache
				cache_IANA_TLD.put(TLD,  this);								
			}
			
			else if(line.toLowerCase().startsWith("domain name:"))
				domain_name = line.substring(12).trim();
			
			else if(line.toLowerCase().startsWith("registry domain id:"))
				this.registry_domain_id = line.substring(19).trim();
			
			else if(line.toLowerCase().startsWith("domain id:"))
				this.registry_domain_id = line.substring(10).trim();
			
			else if(line.toLowerCase().startsWith("registrar whois server:"))
			{
				this.registrar_whois_server = line.substring(23).trim();
				REGISTRAR_WHOIS_SERVER = registrar_whois_server;
			}
			
			else if(line.toLowerCase().startsWith("domain name registrar server:"))
			{
				this.registrar_whois_server = line.substring(29).trim();
				REGISTRAR_WHOIS_SERVER = registrar_whois_server;
			}
			
			else if(line.toLowerCase().startsWith("registrar url:"))
				this.registrar_url = line.substring(14).trim();
			
			else if(line.toLowerCase().startsWith("updated date:"))
				this.updated_date = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("creation date:"))
				this.creation_date = line.substring(14).trim();
			
			else if(line.toLowerCase().startsWith("registry expiry date:"))
				this.registrar_registration_expiration_date = line.substring(21).trim();
			
			else if(line.toLowerCase().startsWith("registrar registration expiration date:"))
				this.registrar_registration_expiration_date = line.substring(39).trim();
			
			else if(line.toLowerCase().startsWith("registrar:"))
				this.registrar = line.substring(10).trim();
			
			else if(line.toLowerCase().startsWith("sponsoring registrar:"))
				this.registrar = line.substring(21).trim();
			
			else if(line.toLowerCase().startsWith("registrar iana id:"))
				this.registrar_iana_id = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("sponsoring registrar iana id:"))
				this.registrar_iana_id = line.substring(29).trim();
			
			else if(line.toLowerCase().startsWith("registrar abuse contact email:"))
				this.registrar_abuse_contact_email = line.substring(30).trim();
			
			else if(line.toLowerCase().startsWith("registrar_abuse_contact_ext:"))
				this.registrar_abuse_contact_ext = line.substring(28).trim();
			
			else if(line.toLowerCase().startsWith("registrar abuse contact phone:"))
				this.registrar_abuse_contact_phone = line.substring(30).trim();
			
			else if(line.toLowerCase().startsWith("registrar abuse contact ext:"))
				this.registrar_abuse_contact_ext = line.substring(28).trim();
			
			else if(line.toLowerCase().startsWith("domain status:"))
			{
				if(domain_status1 == null)
					this.domain_status1 = line.substring(14).trim();
				
				else if(domain_status2 == null)
					this.domain_status2 = line.substring(14).trim();
				
				else if(domain_status3 == null)
					this.domain_status3 = line.substring(14).trim();
				
				else if(domain_status4 == null)
					this.domain_status4 = line.substring(14).trim();
				
				else if(domain_status5 == null)
					this.domain_status5 = line.substring(14).trim();
				
				else if(domain_status6 == null)
					this.domain_status6 = line.substring(14).trim();
				
				else if(domain_status7 == null)
					this.domain_status7 = line.substring(14).trim();
				
				else if(domain_status8 == null)
					this.domain_status8 = line.substring(14).trim();
				
				else if(domain_status9 == null)
					this.domain_status9 = line.substring(14).trim();
				
				else if(domain_status10 == null)
					this.domain_status10 = line.substring(14).trim();
			}
			
			else if(line.toLowerCase().startsWith("name server:"))
			{
				if(name_server_NAME1 == null)
				{
					this.name_server_NAME1 = line.substring(12).trim();
					this.name_server_IP1 = this.ping(this.name_server_NAME1, PING_COUNT, false);
				}
				
				else if(name_server_NAME2 == null)
				{
					this.name_server_NAME2 = line.substring(12).trim();
					this.name_server_IP2 = this.ping(this.name_server_NAME2, PING_COUNT, false);
				}
				
				else if(name_server_NAME3 == null)
				{
					this.name_server_NAME3 = line.substring(12).trim();
					this.name_server_IP3 = this.ping(this.name_server_NAME3, PING_COUNT, false);
				}
				
				else if(name_server_NAME4 == null)
				{
					this.name_server_NAME4 = line.substring(12).trim();
					this.name_server_IP4 = this.ping(this.name_server_NAME4, PING_COUNT, false);
				}
				
				else if(name_server_NAME5 == null)
				{
					this.name_server_NAME5 = line.substring(12).trim();
					this.name_server_IP5 = this.ping(this.name_server_NAME5, PING_COUNT, false);
				}
				
				else if(name_server_NAME6 == null)
				{
					this.name_server_NAME6 = line.substring(12).trim();
					this.name_server_IP6 = this.ping(this.name_server_NAME6, PING_COUNT, false);
				}
				
				else if(name_server_NAME7 == null)
				{
					this.name_server_NAME7 = line.substring(12).trim();
					this.name_server_IP7 = this.ping(this.name_server_NAME7, PING_COUNT, false);
				}
				
				else if(name_server_NAME8 == null)
				{
					this.name_server_NAME8 = line.substring(12).trim();
					this.name_server_IP8 = this.ping(this.name_server_NAME8, PING_COUNT, false);
				}
				
				else if(name_server_NAME9 == null)
				{
					this.name_server_NAME9 = line.substring(12).trim();
					this.name_server_IP9 = this.ping(this.name_server_NAME9, PING_COUNT, false);
				}
				
				else if(name_server_NAME10 == null)
				{
					this.name_server_NAME10 = line.substring(12).trim();
					this.name_server_IP10 = this.ping(this.name_server_NAME10, PING_COUNT, false);
				}
				
				else if(name_server_NAME11 == null)
				{
					this.name_server_NAME11 = line.substring(12).trim();
					this.name_server_IP11 = this.ping(this.name_server_NAME11, PING_COUNT, false);
				}
				
				else if(name_server_NAME12 == null)
				{
					this.name_server_NAME12 = line.substring(12).trim();
					this.name_server_IP12 = this.ping(this.name_server_NAME12, PING_COUNT, false);
				}
				
				else if(name_server_NAME13 == null)
				{
					this.name_server_NAME13 = line.substring(12).trim();
					this.name_server_IP13 = this.ping(this.name_server_NAME13, PING_COUNT, false);
				}
				
				else if(name_server_NAME14 == null)
				{
					this.name_server_NAME14 = line.substring(12).trim();
					this.name_server_IP14 = this.ping(this.name_server_NAME14, PING_COUNT, false);
				}
				
				else if(name_server_NAME15 == null)
				{
					this.name_server_NAME15 = line.substring(12).trim();
					this.name_server_IP15 = this.ping(this.name_server_NAME15, PING_COUNT, false);		
				}
				
				else if(name_server_NAME16 == null)
				{
					this.name_server_NAME16 = line.substring(12).trim();
					this.name_server_IP16 = this.ping(this.name_server_NAME16, PING_COUNT, false);
				}
				
				else if(name_server_NAME17 == null)
				{
					this.name_server_NAME17 = line.substring(12).trim();
					this.name_server_IP17 = this.ping(this.name_server_NAME17, PING_COUNT, false);
				}
				
				else if(name_server_NAME18 == null)
				{
					this.name_server_NAME18 = line.substring(12).trim();
					this.name_server_IP18 = this.ping(this.name_server_NAME18, PING_COUNT, false);
				}
				
				else if(name_server_NAME19 == null)
				{
					this.name_server_NAME19 = line.substring(12).trim();
					this.name_server_IP19 = this.ping(this.name_server_NAME19, PING_COUNT, false);
				}
				
				else if(name_server_NAME20 == null)
				{
					this.name_server_NAME20 = line.substring(12).trim();
					this.name_server_IP20 = this.ping(this.name_server_NAME20, PING_COUNT, false);
				}
			}
			
			else if(line.toLowerCase().startsWith("name server ip:"))
			{
				if(name_server_IP1 == null)
				{
					this.name_server_IP1 = line.substring(15).trim();
					//this.name_server_IP1 = this.ping(this.name_server_IP1, PING_COUNT, false);
				}
				
				else if(name_server_IP2 == null)
				{
					this.name_server_IP2 = line.substring(15).trim();
					//this.name_server_IP2 = this.ping(this.name_server_IP2, PING_COUNT, false);
				}
				
				else if(name_server_IP3 == null)
				{
					this.name_server_IP3 = line.substring(15).trim();
					//this.name_server_IP3 = this.ping(this.name_server_IP3, PING_COUNT, false);
				}
				
				else if(name_server_IP4 == null)
				{
					this.name_server_IP4 = line.substring(15).trim();
					//this.name_server_IP4 = this.ping(this.name_server_IP4, PING_COUNT, false);
				}
				
				else if(name_server_IP5 == null)
				{
					this.name_server_IP5 = line.substring(15).trim();
					//this.name_server_IP5 = this.ping(this.name_server_IP5, PING_COUNT, false);
				}
				
				else if(name_server_IP6 == null)
				{
					this.name_server_IP6 = line.substring(15).trim();
					//this.name_server_IP6 = this.ping(this.name_server_IP6, PING_COUNT, false);
				}
				
				else if(name_server_IP7 == null)
				{
					this.name_server_IP7 = line.substring(15).trim();
					//this.name_server_IP7 = this.ping(this.name_server_IP7, PING_COUNT, false);
				}
				
				else if(name_server_IP8 == null)
				{
					this.name_server_IP8 = line.substring(15).trim();
					//this.name_server_IP8 = this.ping(this.name_server_IP8, PING_COUNT, false);
				}
				
				else if(name_server_IP9 == null)
				{
					this.name_server_IP9 = line.substring(15).trim();
					//this.name_server_IP9 = this.ping(this.name_server_IP9, PING_COUNT, false);
				}
				
				else if(name_server_IP10 == null)
				{
					this.name_server_IP10 = line.substring(15).trim();
					//this.name_server_IP10 = this.ping(this.name_server_IP10, PING_COUNT, false);
				}
				
				else if(name_server_IP11 == null)
				{
					this.name_server_IP11 = line.substring(15).trim();
					//this.name_server_IP11 = this.ping(this.name_server_IP11, PING_COUNT, false);
				}
				
				else if(name_server_IP15 == null)
				{
					this.name_server_IP15 = line.substring(15).trim();
					//this.name_server_IP15 = this.ping(this.name_server_IP15, PING_COUNT, false);
				}
				
				else if(name_server_IP13 == null)
				{
					this.name_server_IP13 = line.substring(15).trim();
					//this.name_server_IP13 = this.ping(this.name_server_IP13, PING_COUNT, false);
				}
				
				else if(name_server_IP14 == null)
				{
					this.name_server_IP14 = line.substring(15).trim();
					//this.name_server_IP14 = this.ping(this.name_server_IP14, PING_COUNT, false);
				}
				
				else if(name_server_IP15 == null)
				{
					this.name_server_IP15 = line.substring(15).trim();
					//this.name_server_IP15 = this.ping(this.name_server_IP15, PING_COUNT, false);		
				}
				
				else if(name_server_IP16 == null)
				{
					this.name_server_IP16 = line.substring(15).trim();
					//this.name_server_IP16 = this.ping(this.name_server_IP16, PING_COUNT, false);
				}
				
				else if(name_server_IP17 == null)
				{
					this.name_server_IP17 = line.substring(15).trim();
					//this.name_server_IP17 = this.ping(this.name_server_IP17, PING_COUNT, false);
				}
				
				else if(name_server_IP18 == null)
				{
					this.name_server_IP18 = line.substring(15).trim();
					//this.name_server_IP18 = this.ping(this.name_server_IP18, PING_COUNT, false);
				}
				
				else if(name_server_IP19 == null)
				{
					this.name_server_IP19 = line.substring(15).trim();
					//this.name_server_IP19 = this.ping(this.name_server_IP19, PING_COUNT, false);
				}
				
				else if(name_server_IP20 == null)
				{
					this.name_server_IP20 = line.substring(15).trim();
					//this.name_server_IP20 = this.ping(this.name_server_IP20, PING_COUNT, false);
				}
			}
			
			else if(line.toLowerCase().startsWith("dnssec:"))
				this.dnssec = line.substring(7).trim();
			
			/*else if(line.toLowerCase().startsWith("registrar registration expiration date:"))
				this.registrar_registration_expiration_date = line.substring(39).trim();*/ //<-- see registry_expiry_date
			
			else if(line.toLowerCase().startsWith("whois server:"))
				this.whois_server = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("referral url:"))
				this.referral_url = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("registry registrant id:"))
				this.registry_registrant_id = line.substring(23).trim();
			
			else if(line.toLowerCase().startsWith("registrant name:"))
				this.registrant_name = line.substring(16).trim();
			
			else if(line.toLowerCase().startsWith("registrant organization:"))
				this.registrant_organization = line.substring(24).trim();
			
			else if(line.toLowerCase().startsWith("registrant street:"))
				this.registrant_street = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("registrant city:"))
				this.registrant_city = line.substring(16).trim();
			
			else if(line.toLowerCase().startsWith("registrant state province:"))
				this.registrant_state_province = line.substring(26).trim();
			
			else if(line.toLowerCase().startsWith("registrant state/province:"))
				this.registrant_state_province = line.substring(26).trim();
			
			else if(line.toLowerCase().startsWith("registrant postal code:"))
				this.registrant_postal_code = line.substring(23).trim();
			
			else if(line.toLowerCase().startsWith("registrant country:"))
				this.registrant_country = line.substring(19).trim();
			
			else if(line.toLowerCase().startsWith("registrant phone:"))
				this.registrant_phone = line.substring(17).trim();
			
			else if(line.toLowerCase().startsWith("registrant phone ext:"))
				this.registrant_phone_ext = line.substring(21).trim();
			
			else if(line.toLowerCase().startsWith("registrant fax:"))
				this.registrant_fax = line.substring(15).trim();
			
			else if(line.toLowerCase().startsWith("registrant fax ext:"))
				this.registrant_fax_ext = line.substring(19).trim();
			
			else if(line.toLowerCase().startsWith("registrant email:"))
				this.registrant_email = line.substring(17).trim();
			
			else if(line.toLowerCase().startsWith("registry admin id:"))
				this.registry_admin_id = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("admin name:"))
				this.admin_name = line.substring(11).trim();
			
			else if(line.toLowerCase().startsWith("admin organization:"))
				this.admin_organization = line.substring(19).trim();
			
			else if(line.toLowerCase().startsWith("admin street:"))
				this.admin_street = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("admin city:"))
				this.admin_city = line.substring(11).trim();
			
			else if(line.toLowerCase().startsWith("admin state province:"))
				this.admin_state_province = line.substring(21).trim();
			
			else if(line.toLowerCase().startsWith("admin state/province:"))
				this.admin_state_province = line.substring(21).trim();
			
			else if(line.toLowerCase().startsWith("admin postal code:"))
				this.admin_postal_code = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("admin country:"))
				this.admin_country = line.substring(14).trim();
			
			else if(line.toLowerCase().startsWith("admin phone:"))
				this.admin_phone = line.substring(12).trim();
			
			else if(line.toLowerCase().startsWith("admin phone ext:"))
				this.admin_phone_ext = line.substring(16).trim();
			
			else if(line.toLowerCase().startsWith("admin fax:"))
				this.admin_fax = line.substring(10).trim();
			
			else if(line.toLowerCase().startsWith("admin fax ext:"))
				this.admin_fax_ext = line.substring(14).trim();
			
			else if(line.toLowerCase().startsWith("admin email:"))
				this.admin_email = line.substring(12).trim();
			
			else if(line.toLowerCase().startsWith("registry tech id:"))
				this.registry_tech_id = line.substring(17).trim();
			
			else if(line.toLowerCase().startsWith("tech id:"))
				this.registry_tech_id = line.substring(8).trim();
			
			else if(line.toLowerCase().startsWith("tech name:"))
				this.tech_name = line.substring(10).trim();
			
			else if(line.toLowerCase().startsWith("tech organization:"))
				this.tech_organization = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("tech street:"))
				this.tech_street = line.substring(12).trim();
			
			else if(line.toLowerCase().startsWith("tech city:"))
				this.tech_city = line.substring(10).trim();
			
			else if(line.toLowerCase().startsWith("tech state province:"))
				this.tech_state_province = line.substring(20).trim();
			
			else if(line.toLowerCase().startsWith("tech state/province:"))
				this.tech_state_province = line.substring(20).trim();
			
			else if(line.toLowerCase().startsWith("tech postal code:"))
				this.tech_postal_code = line.substring(17).trim();
			
			else if(line.toLowerCase().startsWith("tech country:"))
				this.tech_country = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("tech phone:"))
				this.tech_phone = line.substring(11).trim();
			
			else if(line.toLowerCase().startsWith("tech phone ext:"))
				this.tech_phone_ext = line.substring(15).trim();
			
			else if(line.toLowerCase().startsWith("tech fax:"))
				this.tech_fax = line.substring(9).trim();
			
			else if(line.toLowerCase().startsWith("tech fax ext:"))
				this.tech_fax_ext = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("tech email:"))
				this.tech_email = line.substring(11).trim();
			
			else if(line.toLowerCase().startsWith("billing id:"))
				this.billing_id = line.substring(11).trim();
			
			else if(line.toLowerCase().startsWith("billing_name:"))
				this.billing_name = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("billing organization:"))
				this.billing_organization = line.substring(21).trim();
			
			else if(line.toLowerCase().startsWith("billing street:"))
				this.billing_street = line.substring(15).trim();
			
			else if(line.toLowerCase().startsWith("billing city:"))
				this.billing_city = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("billing state province:"))
				this.billing_state_province = line.substring(23).trim();
			
			else if(line.toLowerCase().startsWith("billing state_province:"))
				this.billing_state_province = line.substring(23).trim();
			
			else if(line.toLowerCase().startsWith("billing state/province:"))
				this.billing_state_province = line.substring(23).trim();
			
			else if(line.toLowerCase().startsWith("billing postal code:"))
				this.billing_postal_code = line.substring(20).trim();
			
			else if(line.toLowerCase().startsWith("billing country:"))
				this.billing_country = line.substring(16).trim();
			
			else if(line.toLowerCase().startsWith("billing phone:"))
				this.billing_phone = line.substring(14).trim();
			
			else if(line.toLowerCase().startsWith("billing phone_ext:"))
				this.billing_phone_ext = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("billing fax:"))
				this.billing_fax = line.substring(12).trim();
			
			else if(line.toLowerCase().startsWith("billing fax ext:"))
				this.billing_fax_ext = line.substring(16).trim();
			
			else if(line.toLowerCase().startsWith("billing_id:"))
				this.billing_id = line.substring(11).trim();
			
			else if(line.toLowerCase().startsWith("billing_organization:"))
				this.billing_organization = line.substring(21).trim();
			
			else if(line.toLowerCase().startsWith("billing_street:"))
				this.billing_street = line.substring(15).trim();
			
			else if(line.toLowerCase().startsWith("billing_city:"))
				this.billing_city = line.substring(13).trim();
			
			else if(line.toLowerCase().startsWith("billing_state_province:"))
				this.billing_state_province = line.substring(23).trim();
			
			else if(line.toLowerCase().startsWith("billing_state/province:"))
				this.billing_state_province = line.substring(23).trim();
			
			else if(line.toLowerCase().startsWith("billing_postal_code:"))
				this.billing_postal_code = line.substring(20).trim();
			
			else if(line.toLowerCase().startsWith("billing_country:"))
				this.billing_country = line.substring(16).trim();
			
			else if(line.toLowerCase().startsWith("billing_phone:"))
				this.billing_phone = line.substring(14).trim();
			
			else if(line.toLowerCase().startsWith("billing_phone_ext:"))
				this.billing_phone_ext = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("billing_fax:"))
				this.billing_fax = line.substring(12).trim();
			
			else if(line.toLowerCase().startsWith("billing_fax_ext:"))
				this.billing_fax_ext = line.substring(16).trim();
			
			else if(line.toLowerCase().startsWith("first lookup date:"))
				this.first_lookup_date = line.substring(18).trim();
			
			else if(line.toLowerCase().startsWith("last lookup date:"))
				this.last_lookup_date = line.substring(17).trim();
			
			else if(line.toLowerCase().startsWith("tld:"))
				this.TLD = line.substring(4).trim();
			
			else if(line.toLowerCase().startsWith("tld registrar server:"))
			{
				this.TLD_WHOIS_REGISTRAR = line.substring(21).trim();
				this.TLD_WHOIS_REGISTRAR_FULL_LINE = line.substring(21).trim();
			}
			
			else if(line.toLowerCase().startsWith("nslookup_request:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.request = line.substring(17);
			}
			
			
			else if(line.toLowerCase().startsWith("nslookup_server:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.server = line.substring(16);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_address_1:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.address_1 = line.substring(19);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_name:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.name = line.substring(14);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_address_2:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.address_2 = line.substring(19);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_ipv4_first:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv4_first = line.substring(20);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_ipv6_first:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv6_first = line.substring(20);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_ipv4:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv4 = line.substring(14);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_ipv6:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.ipv6 = line.substring(14);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_last_retrieved:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.last_retrieved = line.substring(24);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_last_update_time:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				try	{	node_nslookup.last_update_time = Long.parseLong(line.substring(26).trim());}catch(Exception e){}
			}
			
			else if(line.toLowerCase().startsWith("nslookup_authoritative:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.authoritative = line.substring(23);
			}
			
			else if(line.toLowerCase().startsWith("nslookup_source:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				//node_nslookup.SOURCE = line.substring(16);
			}
			
			
			else if(line.toLowerCase().startsWith("nslookup_authoritative:"))
			{
				if(this.node_nslookup == null)
					node_nslookup = new Node_Nslookup();
								
				node_nslookup.authoritative = line.substring(23);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_request:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.request = line.substring(18);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_ip:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.ip = line.substring(13);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_country_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.country_code = line.substring(23);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_country_name:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.country_name = line.substring(23);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_region_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.country_code = line.substring(22);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_region_name:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.region_state_name = line.substring(22);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_city:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.city = line.substring(15);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_zip_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.zip_code = line.substring(19);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_time_zone:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.time_zone = line.substring(20);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_latitude:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.latitude = line.substring(19);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_longitude:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.longitude = line.substring(20);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_metro_code:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.metro_area_code = line.substring(21);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_last_retrieved:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.last_retrieved = line.substring(25);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_last_updated:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.timeStamp = line.substring(23);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_source:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				//node_geo.SOURCE = line.substring(17);
			}
			
			else if(line.toLowerCase().startsWith("geolookup_authoritative:"))
			{
				if(this.node_geo == null)
					node_geo = new Node_GeoIP();
								
				node_geo.authoritative = line.substring(24);
			}
			
			
			
			else
				driver.directive("Unknown field [" + line + "]");
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parse_whois_server", e);
			e.printStackTrace(System.out);
		}
		
		return false;
	}
	
	
	public boolean sop(String out)
	{
		try
		{
			if(debug)
				driver.directive(out);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "sop", e);
		}
		
		return false;
	}
	
	
	public static boolean update_geo()
	{
		try
		{
			//search through and attempt to update nodes without a geo allocation
			
			if(Node_GeoIP.geo_requests_per_hour_count > Node_GeoIP.max_geo_requests_per_hour)
				return false;
			
			for(Whois whois : Whois.tree_whois_lookup.values())
			{
				try
				{
					if(whois.node_geo == null || whois.node_geo.latitude == null || whois.node_geo.latitude.trim().equals(""))
					{
						//look it up, and assign if successful
						Node_GeoIP geo = new Node_GeoIP(whois.LOOKUP, false);
						
						if(geo.parse_complete)
							whois.node_geo = geo;
					}
						
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "update_geo", e, -1);
					continue;
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_geo", e);
		}
		
		return false;
	}
	
	
	public static Whois resolve(String line)
	{
		try
		{
			if(line.startsWith(":"))
				line = line.substring(1).trim();
			
			if(Whois.tree_whois_lookup.containsKey(line.toLowerCase()))
				return Whois.tree_whois_lookup.get(line.toLowerCase());
			
			Whois whois = new Whois(line, Whois_Driver.EXECUTION_ACTION_PERFORM_WHOIS_LOOKUP, false);
			
			return whois;		
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "resolve", e);
		}
		
		return null;
	}
	
	
	
	public File map_whois()
	{
		try
		{
			File fle = new File("./map");
			if(!fle.exists() || !fle.isDirectory())
				fle.mkdirs();
			
			if(fle.getCanonicalPath().endsWith(File.separator))
				fle = new File(fle.getCanonicalPath() + this.DOMAIN_NAME + driver.get_time_stamp("_") + ".html");
			else 
				fle = new File(fle.getCanonicalPath() + File.separator + this.DOMAIN_NAME + driver.get_time_stamp("_") + ".html");
			
			PrintWriter pwOut = new PrintWriter(new FileWriter(fle), true);
			
			pwOut.println("<html><head><meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">");
			pwOut.println("</head><body><b>" + driver.FULL_NAME + "  by Solomon Sonya @Carpenter1010    2017-11-05-00:56.23</b> <br><br>");
			
			pwOut.println("<b>WHOIS</b><hr><br>");
			this.print_whois(pwOut);
			
			if(this.node_nslookup != null && this.node_nslookup.parse_complete)
			{
				pwOut.println("<br><b>NSLOOKUP</b><hr>");
				pwOut.println(this.node_nslookup.get_map_details());
			}
			
			if(node_geo == null && Node_GeoIP.cache_FOUND.containsKey(DOMAIN_NAME.toLowerCase().trim()))
			{
				node_geo = Node_GeoIP.cache_FOUND.get(DOMAIN_NAME.toLowerCase().trim());
			}
			
			if(node_geo != null && this.node_geo.parse_complete)
			{
				pwOut.println(this.node_geo.get_web_HTML_formatted("View on Google Map", node_geo));			
			}
			
			pwOut.println("</body></html>");
			
			pwOut.flush();
			try	{	pwOut.close();} catch(Exception e){}
			
			if(fle.exists())
			{
				driver.directive("Complete! If successful, map has been written to \"" + fle.getCanonicalPath() + "\"");
			}
			
			if(driver.isWindows)
			{
				try	{	Process p = Runtime.getRuntime().exec("explorer.exe " + fle.getCanonicalPath());	}	catch(Exception e){}
			}


			
			return fle;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "map_whois", e);
		}
		
		return null;
	}
	
	
	
	
	
	public String get_whois_data_line(String delimiter, String nslookup_tuple, String geo_tuple)
	{
		try
		{
			delimiter = " " + delimiter;
			
			return 
			"TLD:   " + this.TLD + delimiter + 
			"TLD Registrar Server:   " + this.TLD_WHOIS_REGISTRAR + delimiter + 
			"Domain Name Registrar Server:   " + this.REGISTRAR_WHOIS_SERVER + delimiter + 
			("Domain Name:   " + domain_name + "") + delimiter + 
			("Registry Domain ID:   " + registry_domain_id + "") + delimiter + 
			("Registrar Whois Server:   " + registrar_whois_server + "") + delimiter + 
			("Registrar Url:   " + registrar_url + "") + delimiter + 
			("Updated Date:   " + updated_date + "") + delimiter + 
			("Creation Date:   " + creation_date + "") + delimiter + 
			("Registrar Registration Expiration Date:   " + registrar_registration_expiration_date + "") + delimiter + 
			("Registrar:   " + registrar + "") + delimiter + 
			("Registrar Iana ID:   " + registrar_iana_id + "") + delimiter + 
			("Registrar Abuse Contact Email:   " + registrar_abuse_contact_email + "") + delimiter + 
			("Registrar Abuse Contact Phone:   " + registrar_abuse_contact_phone + "") + delimiter + 

			("registrar_abuse_contact_ext:   " + registrar_abuse_contact_ext + "") + delimiter + 

			
			
			(get_domain_status_list( " " + this.delimiter1, false)) + delimiter + 

			
			("Registry Registrant ID:   " + registry_registrant_id + "") + delimiter + 
			("Registrant Name:   " + registrant_name + "") + delimiter + 
			("Registrant Organization:   " + registrant_organization + "") + delimiter + 
			("Registrant Street:   " + registrant_street + "") + delimiter + 
			("Registrant City:   " + registrant_city + "") + delimiter + 
			("Registrant State Province:   " + registrant_state_province + "") + delimiter + 
			("Registrant Postal Code:   " + registrant_postal_code + "") + delimiter + 
			("Registrant Country:   " + registrant_country + "") + delimiter + 
			("Registrant Phone:   " + registrant_phone + "") + delimiter + 
			("Registrant Phone Ext:   " + registrant_phone_ext + "") + delimiter + 
			("Registrant Fax:   " + registrant_fax + "") + delimiter + 
			("Registrant Fax Ext:   " + registrant_fax_ext + "") + delimiter + 
			("Registrant Email:   " + registrant_email + "") + delimiter + 
			
			
			
			("Registry Admin ID:   " + registry_admin_id + "") + delimiter + 
			("Admin Name:   " + admin_name + "") + delimiter + 
			("Admin Organization:   " + admin_organization + "") + delimiter + 
			("Admin Street:   " + admin_street + "") + delimiter + 
			("Admin City:   " + admin_city + "") + delimiter + 
			("Admin State Province:   " + admin_state_province + "") + delimiter + 
			("Admin Postal Code:   " + admin_postal_code + "") + delimiter + 
			("Admin Country:   " + admin_country + "") + delimiter + 
			("Admin Phone:   " + admin_phone + "") + delimiter + 
			("Admin Phone Ext:   " + admin_phone_ext + "") + delimiter + 
			("Admin Fax:   " + admin_fax + "") + delimiter + 
			("Admin Fax Ext:   " + admin_fax_ext + "") + delimiter + 
			("Admin Email:   " + admin_email + "") + delimiter + 
			
			
			("Registry Tech ID:   " + registry_tech_id + "") + delimiter + 
			("Tech Name:   " + tech_name + "") + delimiter + 
			("Tech Organization:   " + tech_organization + "") + delimiter + 
			("Tech Street:   " + tech_street + "") + delimiter + 
			("Tech City:   " + tech_city + "") + delimiter + 
			("Tech State Province:   " + tech_state_province + "") + delimiter + 
			("Tech Postal Code:   " + tech_postal_code + "") + delimiter + 
			("Tech Country:   " + tech_country + "") + delimiter + 
			("Tech Phone:   " + tech_phone + "") + delimiter + 
			("Tech Phone Ext:   " + tech_phone_ext + "") + delimiter + 
			("Tech Fax:   " + tech_fax + "") + delimiter + 
			("Tech Fax Ext:   " + tech_fax_ext + "") + delimiter + 
			("Tech Email:   " + tech_email + "") + delimiter + 
			
			
			(this.get_name_server_list(" " + delimiter1 + " ", false)) + delimiter + 			
			
			(this.get_name_server_IP_list(" " + delimiter1 + " ", false)) + delimiter + 

			
			("DNSSEC:   " + dnssec + "") + delimiter + 
			
			
			("Whois Server:   " + whois_server + "") + delimiter + 
			
			("Referral URL:   " + referral_url + "") + delimiter + 

			("billing_id:   " + billing_id + "") + delimiter + 
			("billing_name:   " + billing_name + "") + delimiter + 
			("billing_organization:   " + billing_organization + "") + delimiter + 
			("billing_street:   " + billing_street + "") + delimiter + 
			("billing_city:   " + billing_city + "") + delimiter + 
			("billing_state_province:   " + billing_state_province + "") + delimiter + 
			("billing_postal_code:   " + billing_postal_code + "") + delimiter + 
			("billing_country:   " + billing_country + "") + delimiter + 
			("billing_phone:   " + billing_phone + "") + delimiter + 
			("billing_phone_ext:   " + billing_phone_ext + "") + delimiter + 
			("billing_fax:   " + billing_fax + "") + delimiter + 
			("billing_fax_ext:   " + billing_fax_ext + "") + delimiter + 
			
			("first lookup date:   " + first_lookup_date + "") + delimiter + 
			("last lookup date:   " + last_lookup_date + "") + delimiter +

			//nslookup
			nslookup_tuple + delimiter + 
			
			//geo
			geo_tuple;

		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_whois_data_line", e); 
		}
		
		return this.domain_name;
	}
	
	public String get_whois_line_file_header(String delimiter)
	{
		try
		{
			return  
					"tld" + delimiter 	+
					"tld_registrar_server" + delimiter 	+
					"domain_name_registrar_server" + delimiter 	+
					"domain_name" + delimiter 	+ 	
					"registry_domain_id" + delimiter 	+ 	
					"registrar_whois_server" + delimiter 	+ 	
					"registrar_url" + delimiter 	+ 	
					"updated_date" + delimiter 	+ 	
					"creation_date" + delimiter 	+ 	
					"registrar_registration_expiration_date" + delimiter 	+ 	
					"registrar" + delimiter 	+ 	
					"registrar_iana_id" + delimiter 	+ 	
					"registrar_abuse_contact_email" + delimiter 	+ 	
					"registrar_abuse_contact_phone" + delimiter 	+ 	
								
					"registrar_abuse_contact_ext" + delimiter 	+ 	
								
								
								
					"domain_status" + delimiter 	+ 	
								
								
					"registry_registrant_id" + delimiter 	+ 	
					"registrant_name" + delimiter 	+ 	
					"registrant_organization" + delimiter 	+ 	
					"registrant_street" + delimiter 	+ 	
					"registrant_city" + delimiter 	+ 	
					"registrant_state_province" + delimiter 	+ 	
					"registrant_postal_code" + delimiter 	+ 	
					"registrant_country" + delimiter 	+ 	
					"registrant_phone" + delimiter 	+ 	
					"registrant_phone_ext" + delimiter 	+ 	
					"registrant_fax" + delimiter 	+ 	
					"registrant_fax_ext" + delimiter 	+ 	
					"registrant_email" + delimiter 	+ 	
								
								
								
					"registry_admin_id" + delimiter 	+ 	
					"admin_name" + delimiter 	+ 	
					"admin_organization" + delimiter 	+ 	
					"admin_street" + delimiter 	+ 	
					"admin_city" + delimiter 	+ 	
					"admin_state_province" + delimiter 	+ 	
					"admin_postal_code" + delimiter 	+ 	
					"admin_country" + delimiter 	+ 	
					"admin_phone" + delimiter 	+ 	
					"admin_phone_ext" + delimiter 	+ 	
					"admin_fax" + delimiter 	+ 	
					"admin_fax_ext" + delimiter 	+ 	
					"admin_email" + delimiter 	+ 	
								
								
					"registry_tech_id" + delimiter 	+ 	
					"tech_name" + delimiter 	+ 	
					"tech_organization" + delimiter 	+ 	
					"tech_street" + delimiter 	+ 	
					"tech_city" + delimiter 	+ 	
					"tech_state_province" + delimiter 	+ 	
					"tech_postal_code" + delimiter 	+ 	
					"tech_country" + delimiter 	+ 	
					"tech_phone" + delimiter 	+ 	
					"tech_phone_ext" + delimiter 	+ 	
					"tech_fax" + delimiter 	+ 	
					"tech_fax_ext" + delimiter 	+ 	
					"tech_email" + delimiter 	+ 	
								
					"name_server"  + delimiter 	+
								
					"name_server_ip" + delimiter 	+
								
								
					"dnssec" + delimiter 	+ 	
								
								
					"whois_server" + delimiter 	+ 	
								
					"referral_url" + delimiter 	+ 	
								
					"billing_id" + delimiter 	+ 	
					"billing_name" + delimiter 	+ 	
					"billing_organization" + delimiter 	+ 	
					"billing_street" + delimiter 	+ 	
					"billing_city" + delimiter 	+ 	
					"billing_state_province" + delimiter 	+ 	
					"billing_postal_code" + delimiter 	+ 	
					"billing_country" + delimiter 	+ 	
					"billing_phone" + delimiter 	+ 	
					"billing_phone_ext" + delimiter 	+ 	
					"billing_fax" + delimiter 	+ 	
					"billing_fax_ext" + delimiter 	+ 	
								
					"first_lookup_date" + delimiter 	+ 	
					"last_lookup_date" + delimiter 	+ 	
								
					//nslookup			
					"nslookup_request"  + delimiter 	+
					"nslookup_server" + delimiter 	+
					"nslookup_address_1" + delimiter 	+
					"nslookup_name" + delimiter 	+
					"nslookup_address_2" + delimiter 	+
					"nslookup_ipv4_first" + delimiter 	+
					"nslookup_ipv6_first" + delimiter 	+
					"nslookup_ipv4" + delimiter 	+
					"nslookup_ipv6" + delimiter 	+
					"nslookup_last_retrieved" + delimiter 	+
					"nslookup_last_update_time" + delimiter 	+
					"nslookup_authoritative" + delimiter 	+
					"nslookup_source" + delimiter 	+
 	
								
					//geo			
					"geolookup_request" + delimiter 	+
					"geolookup_ip" + delimiter 	+
					"geolookup_country_code" + delimiter 	+
					"geolookup_country_name" + delimiter 	+
					"geolookup_region_code" + delimiter 	+
					"geolookup_region_name" + delimiter 	+
					"geolookup_city" + delimiter 	+
					"geolookup_zip_code" + delimiter 	+
					"geolookup_time_zone" + delimiter 	+
					"geolookup_latitude" + delimiter 	+
					"geolookup_longitude" + delimiter 	+
					"geolookup_metro_code" + delimiter 	+
					"geolookup_last_update_time" + delimiter 	+
					"geolookup_last_retrieved" + delimiter 	+
					"geolookup_source" + delimiter 	+
					"geolookup_authoritative"
					;			
								


		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_whois_line_file_header", e);
		}
		
		return " - ";
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
