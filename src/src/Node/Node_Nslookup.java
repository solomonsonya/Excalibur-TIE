package Node;

/**
 * @author Solomon Sonya  
 * 
 * Solo, future update, parse command -->nslookup -type=any yahoo.com
 * */

import javax.swing.*;
import javax.swing.Timer;

import Driver.Driver;
import Driver.Log;

import java.util.*;
import java.io.*;
import java.text.SimpleDateFormat;
import java.awt.event.*;

public class Node_Nslookup extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Node_Nslookup";
	public static volatile Driver driver = new Driver();
	
	public static volatile Log nslookup_not_found = null;
	public static volatile Log nslookup_found = null;
	
	public static volatile boolean degub = false;
	
	//public static volatile Node_Nslookup NSLOOKUP = new Node_Nslookup();
	
	public static volatile boolean NSLOOKUP_ENABLED = true;
	
	public static volatile LinkedList<Node_Nslookup> queue_nslookup = new LinkedList<Node_Nslookup>();
	
	public static volatile LinkedList<File> list_import_file = new LinkedList<File>();
	
	public static final boolean override_nslookup_entry = false;
	
	public volatile String request = "";
	public volatile String server = "";
	public volatile String address_1 = "";
	public volatile String name = "";
	public volatile String address_2 = "";
	public volatile String value = "";
	public String ipv4 = "", ipv4_first = "";
	public String ipv6 = "", ipv6_first = "";
	public volatile String last_retrieved = new SimpleDateFormat("yyyy-MM-dd-HH:mm.ss").format(new Date());
	public long last_update_time = System.currentTimeMillis();
	public static final String SOURCE = Driver.NAME + "_" + "NSLOOKUP";
	public volatile String authoritative = driver.authoritative_not_found;
	
	public volatile boolean parse_complete = false;
	
	public static final int timeout = 30 * 1000;

	public static TreeMap<String, Node_Nslookup> cache_nslookup_FOUND = new TreeMap<String, Node_Nslookup>();	
	public static TreeMap<String, Node_Nslookup> cache_nslookup_NOT_FOUND = new TreeMap<String, Node_Nslookup>();
	
	public volatile boolean allow_multiple_addresses = false;
	
	public volatile String [] array = null;
	
	javax.swing.Timer tmr_check_queue = null;
	
	public volatile boolean process_interrupt = true, process_import_interrupt = true;
	
	public File fle_to_import = null;
	
	public static final String BLANK_ROW = " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" ;
	
	public static volatile boolean debug = false;
	
	public Node_Nslookup() 
	{
		try
		{
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	} 	
	
	public Node_Nslookup(String line_to_parse)
	{
		try
		{
			this.parse(line_to_parse);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 4", e);
		}
	}
	
	public Node_Nslookup(boolean start_thread) //ONLY USE THIS TO START THE THREAD!
	{
		try
		{
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	} 	
	
		
	public Node_Nslookup(String req, boolean execute_ns_lookup)
	{
		try
		{
			request = req;
			
			if(execute_ns_lookup)
				nslookup(req);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
		}
	}
			
	public Node_Nslookup(File fle)
	{
		try
		{
			fle_to_import = fle;	
			this.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 5", e);
		}
		
	}
	
	private boolean nslookup(String addr)
	{
		try
		{
			if(!NSLOOKUP_ENABLED)
				return false;
			
			if(addr == null || addr.equals(""))
				return false;
			
			addr = addr.trim();
				
			//
			//notify
			//
			sop("\nResolving nslookup " + addr);
			
			//
			//otherwise, attempt to lookup
			//
			Process proc = Runtime.getRuntime().exec("nslookup " + addr);
			String line = "";
			
			request = addr;
			
			BufferedReader brIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
			while((line = brIn.readLine()) != null)
			{
				try
				{
					line = line.trim();
					
					if(line.equals(""))
						continue;
					
					parse(line);										
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "nslookup_stdout", e, -1);
					continue;
				}
				
			}
			
			try	{	brIn.close();	}	catch(Exception e){}
			
			//
			//check if we received ERROR data from the process
			//
			if(address_2 == null  || address_2.trim().equals(""))
			{
				//nothing fully received, thus try to read the error stream
				brIn = new BufferedReader(new InputStreamReader(proc.getErrorStream()));
				while((line = brIn.readLine()) != null)
				{
					try
					{
						line = line.trim();
						
						if(line.equals(""))
							continue;
						
						parse(line);										
					}
					catch(Exception e)
					{
						driver.eop_loop(myClassName, "nslookup_error_stream", e, -1);
						continue;
					}
					
				}
				
				try	{	brIn.close();	}	catch(Exception e){}
				
			}
			
			//
			//check if we have a host name, or if we need to try to resolve that as well
			//
			if(this.name == null || name.trim().equals("") || name.toLowerCase().trim().equals(request))
			{
				String ip = "";
				
				if(this.ipv4_first != null && !this.ipv4_first.trim().equals(""))
					ip = this.ipv4_first;
				else if(this.ipv6_first != null && !this.ipv6_first.trim().equals(""))
					ip = this.ipv6_first;
				
				//only proceed if we have an ip address to query
				if(ip != null && !ip.trim().equals(""))
				{
					proc = Runtime.getRuntime().exec("nslookup " + ip);
					line = "";					
					
					brIn = new BufferedReader(new InputStreamReader(proc.getInputStream()));
					while((line = brIn.readLine()) != null)
					{
						try
						{
							line = line.trim();
							
							if(line.equals(""))
								continue;
							
							parse(line);										
						}
						catch(Exception e)
						{
							driver.eop_loop(myClassName, "nslookup_ address", e, -1);
							continue;
						}
						
					}
					
					try	{	brIn.close();	}	catch(Exception e){}
				}
				
				
			}
			
			//let node add self to the appropriate cache via the parse mtd
									
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "nslookup", e);
		}
		
		return false;
	}
	
	/**
	 * live parse line from the socket to the nslookup server
	 * @param line
	 * @return
	 */
	public boolean parse(String line)
	{
		try
		{
			if(line == null || line.trim().equals(""))
				return false;
			
			
			line = line.trim();
			
			//sop("parse-->" + line);
			
			//
			//Non-authoritative answer:
			//
			if(line.toLowerCase().startsWith("non-authoritative answer:"))
				return false;
			if(line.toLowerCase().startsWith("non authoritative answer:"))
				return false;
			
			//
			//REQUEST TIMED OUT
			//
			else if(line.toLowerCase().contains("request timed out") || line.toLowerCase().contains("timeout was") || line.toLowerCase().contains("no response from server"))
			{
				sop("ERROR! cannot complete nslookup [" + request + "] --> \"" + line + "\" Check your firewall settings or internet connection...");
				return false;
			}	
			
			//
			//can't find
			//
			else if(line.toLowerCase().contains("can't find") || line.toLowerCase().contains("cant find"))
			{
				if(!cache_nslookup_NOT_FOUND.containsKey(request))
				{
					cache_nslookup_NOT_FOUND.put(request, this);

					if(nslookup_not_found == null)
						nslookup_not_found = new Log("nslookup_not_found",  "nslookup_not_found", 250, 999999999);
					
					nslookup_not_found.log(request);
					
					
					sop("* * * nslookup failed for address [" + request + "]");		
				}
				
				return false;
			}
			
			//
			//non-existent domain!
			//
			else if(line.toLowerCase().contains("non-existent domain") || line.toLowerCase().contains("non existent domain") || line.toLowerCase().contains("nonexistent domain"))
			{
				if(!cache_nslookup_NOT_FOUND.containsKey(request))
				{
					cache_nslookup_NOT_FOUND.put(request, this);

					if(nslookup_not_found == null)
						nslookup_not_found = new Log("nslookup_not_found",  "nslookup_not_found", 250, 999999999);
					
					nslookup_not_found.log(request);
					
					
					sop("* * * * nslookup failed for address [" + request + "]");		
				}
				
				return false;
			}	
			
			//
			//IMPORT FILE
			//
			if(line.toLowerCase().contains("nslookup_request") && line.toLowerCase().contains("nslookup_server") && line.toLowerCase().contains("nslookup_address_1") && line.toLowerCase().contains("nslookup_name") && line.toLowerCase().contains("nslookup_address_2") && parse_import_file(line))
				return true;
			
			//
			//server
			//
			if(line.startsWith("server:"))
			{
				this.server = line.replaceFirst("server:", "").trim();				
			}
			else if(line.startsWith("Server:"))
			{
				this.server = line.replaceFirst("Server:", "").trim();				
			}						

			//
			//name
			//
			else if(line.startsWith("name:"))
			{
				this.name = line.replaceFirst("name:", "").trim();	
				
				if(this.request == null || this.request.equals(""))
					this.request = name;
				
			}
			else if(line.startsWith("Name:"))
			{
				this.name = line.replaceFirst("Name:", "").trim();	

				if(this.request == null || this.request.equals(""))
					this.request = name;
			}
			
			//
			//address
			//
			else if(line.toLowerCase().trim().startsWith("address:"))
			{
				line = line.replaceFirst("Address:", "").trim();
				
				if(this.address_1 == null || this.address_1.trim().equals(""))
				{
					this.address_1 = line.trim();
				}
				else
				{
					update_address_2(line);
				}
			}
			
			//
			//addresses
			//
			else if(line.toLowerCase().trim().startsWith("addresses:"))
			{
				update_address_2(line);
			}
			
			//
			//otw, add the single line to the address list
			//
			else if(this.allow_multiple_addresses)
				update_address_2(line);
			
			else
				sop("UNKNOWN TOKEN RECEIVED IN [parse mtd] in " + myClassName + "--> " + line);
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parse", e);
		}
		
		return false;
	}
	
	public boolean parse_import_file(String line)
	{
		try
		{
			line = line.replaceAll("\"", "");
			line = line.replaceAll("\\{", "");
			line = line.replaceAll("\\}", "");
			
			String [] arr = null, tuple = null;
			String val = "";
			
			arr = line.split(",");
			
			if(arr == null || arr.length < 1)
				return false;
			
			for(int i = 0; i < arr.length; i++)
			{
				try
				{
					if(arr[i] == null || arr[i].trim().equals(""))
						continue;
					
					tuple = arr[i].split(":");
					
					if(tuple == null || tuple.length < 2)
					{
						//sop("VAL TOO SHORT --> " + arr[i]);
						continue;
					}
					
					val = tuple[1];
					
					//concat ipv6
					for(int j = 2; j < tuple.length; j++)
					{
						val = val + ":" + tuple[j];
					}
					
					val = val.trim();
					
					if(tuple[0].trim().equalsIgnoreCase("nslookup_request"))
						this.request = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_server"))
						this.server = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_address_1"))
						this.address_1 = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_name"))
						this.name = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_address_2"))
					{
						this.address_2 = val;
						parse_complete = true;
					}
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_ipv4_first"))
						this.ipv4_first = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_ipv6_first"))
						this.ipv6_first = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_ipv4"))
						this.ipv4 = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_ipv6"))
						this.ipv6 = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_last_retrieved"))
						this.last_retrieved = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_authoritative"))
						this.authoritative = val;
					else if(tuple[0].trim().equalsIgnoreCase("nslookup_last_update_time"))
						try	{	this.last_update_time = Long.parseLong(val.trim());	}	catch(Exception eee){ last_update_time = System.currentTimeMillis();	}					
					
				}
				catch(Exception ee)
				{
					driver.eop_loop(myClassName, "parse_import_file", ee, i);
					continue;
				}
			}
			
			Node_Nslookup.update_cache(this);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parse_import_file", e);
		}
		
		return false;
	}
	
	public static boolean update_cache(Node_Nslookup node)
	{
		try
		{
			if(node == null)
				return false;
			
			//
			//LINK
			//
			if(!cache_nslookup_FOUND.containsKey(node.request))
			{
				cache_nslookup_FOUND.put(node.request, node);
				
				
				sop("Adding address [" + node.request + "] to the nslookup cache --> " + node.get_json_formatted(false));
				
				
				
				if(nslookup_found == null)
					nslookup_found = new Log("nslookup_found",  "nslookup_found", 250, 999999999);
				
				nslookup_found.log(node.get_json_formatted(false));
				
			}	
			else if(override_nslookup_entry)
			{						
				try	{	sop("Override enabled. Adding address [" + node.request + "] to the nslookup cache --> " + node.get_json_formatted(false) + "  // to replace previous entry " + cache_nslookup_FOUND.get(node.request).get_json_formatted(false));	}	catch(Exception e){sop("error dismissed in " + myClassName + " during import...");}
				cache_nslookup_FOUND.put(node.request, node);


				if(nslookup_found == null)
					nslookup_found = new Log("nslookup_found",  "nslookup_found", 250, 999999999);
				
				nslookup_found.log(node.get_json_formatted(false));
			}
			else
			{
				sop("Duplicate entry already existed for request [" + node.request + "].  Omitting entry [" + node.get_json_formatted(false) + "]");
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_cache", e);
		}
		
		return false;
	}
	
	

	//
	
	/**
	 * determine if we're using an ipv4 or ipv6, and update the string of addresses
	 * @param line
	 * @return
	 */
	public boolean update_address_2(String line)
	{
		try
		{
			if(line.startsWith("Address:"))
				line = line.replaceFirst("Address:", "").trim(); 
			else if(line.startsWith("address:"))
				line = line.replaceFirst("address:", "").trim(); 
			else if(line.startsWith("Addresses:"))
				line = line.replaceFirst("Addresses:", "").trim(); 
			else if(line.startsWith("addresses:"))
				line = line.replaceFirst("addresses:", "").trim(); 			
			
			//
			//update entries
			//
			allow_multiple_addresses = true;
			
			line = line.trim();
			
			if(this.address_2 == null || this.address_2.trim().equals(""))
			{
				this.address_2 = line.trim();		
				
				authoritative = driver.authoritative_found;
				parse_complete = true;
				
			}//add to the address if not already there...
			else if(!this.address_2.contains(line))
			{
				this.address_2 = this.address_2 + "; " + line;			 
			}
			
			//
			//ipv6
			//
			if(line.contains(":"))
			{
				if(this.ipv6_first == null || this.ipv6_first.trim().equals(""))
					ipv6_first = line;
				
				if(this.ipv6 == null || this.ipv6.trim().equals(""))
					ipv6 = line;
				else if(!ipv6.contains(line))//only add if not included
					ipv6 = ipv6 + "; " + line;				
			}
			else //if(line.contains(":"))
			{
				if(this.ipv4_first == null || this.ipv4_first.trim().equals(""))
					ipv4_first = line;
				
				if(this.ipv4 == null || this.ipv4.trim().equals(""))
					ipv4 = line;
				else if(!ipv4.contains(line))//only add if not included
					ipv4 = ipv4 + "; " + line;				
			}

			//
			//add to cache
			//
			if(!cache_nslookup_FOUND.containsKey(request))
			{
				cache_nslookup_FOUND.put(request, this);
				sop("Adding address [" + request + "] to the nslookup cache --> " + this.get_json_formatted(false));


				if(nslookup_found == null)
					nslookup_found = new Log("nslookup_found",  "nslookup_found", 250, 999999999);
				
				nslookup_found.log(this.get_json_formatted(false));
				
				
				
				//
				//remove from not found cache
				//
				if(Node_Nslookup.cache_nslookup_NOT_FOUND.containsKey(request))
				{
					try	{	Node_Nslookup.cache_nslookup_NOT_FOUND.remove(this);	}	catch(Exception e){}
				}
			}

			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_address_2", e);
		}
		
		return false;
	}
	
	/**
	 * nulls are accepted. if null, address_2 will be used
	 * @param addr
	 * @return
	 */
	public long get_ip_to_long(String addr)
	{
		try
		{
			if(addr == null)
				addr = address_2;
				
			//choose valid ipv4 if possible...
			if(addr.contains(","))
			{
				String [] arr = addr.split(",");
				for(String val : arr)
				{
					if(!val.contains(":"))
						return driver.ip_to_long(val);
				}
			}
			
			return driver.ip_to_long(addr);
		}
		catch(Exception e)
		{
			
		}
		
		return -1;
	}
	
	public void run()
	{
		try
		{
			/*sop(myClassName + " started!");
			this.tmr_check_queue = new Timer(60, this);
			tmr_check_queue.start();*/
			
			if(fle_to_import != null && fle_to_import.exists() && fle_to_import.isFile())
				this.import_nslookup_data_file(fle_to_import);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	  
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == this.tmr_check_queue && process_interrupt)
				check_queue();
			/*if(ae.getSource() == this.tmr_check_queue && !list_import_file.isEmpty() && process_import_interrupt)
				import_nslookup_data_file(list_import_file.removeFirst());*/
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
		
	}
	
	public static Node_Nslookup resolve(String addr)
	{
		try
		{
			return get(addr);
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "resolve", e);
		}
		
		return null;
	}
	
	public static Node_Nslookup get(String addr)
	{
		try
		{
			if(!NSLOOKUP_ENABLED)
				return null;
			
			//
			//Check the cache!
			//
			if(cache_nslookup_FOUND.containsKey(addr))
			{
				return cache_nslookup_FOUND.get(addr);
			}
			
			//otw, try to resolve
			Node_Nslookup lookup = new Node_Nslookup(addr, true);
			return lookup;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get", e);
		}
		
		return null;
	}
	
	public boolean check_queue()
	{
		try
		{
			if(!process_interrupt)
				return true;
			
			if(this.queue_nslookup.isEmpty())
				return true;
			
			process_interrupt = false;
			
			sop("READY TO PROCESS QUEUE!");
			
			
			
			process_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "check_queue", e);
		}
		
		
		process_interrupt = true;
		return false;
	}
	
	
	
	public boolean import_nslookup_data_file(File fle)
	{
		try
		{
			if(!process_import_interrupt)
				return false;
			
			process_import_interrupt = false;
			
			if(fle == null || !fle.exists() || !fle.isFile())
			{
				process_import_interrupt = true;
				return false;
			}
			
			driver.directive("Attempting to import nslookup file at \"" + fle.getCanonicalPath() + "\"");
			
			BufferedReader br = new BufferedReader(new FileReader(fle));
			String line = "", val = "";
			int count = 0;
			int before_size = Node_Nslookup.cache_nslookup_FOUND.size();
			String  [] array = null, tuple = null;
			Node_Nslookup n = new Node_Nslookup();

			while((line = br.readLine()) != null)
			{
				try
				{
					if(line.contains(","))
					{						
						sop("LINE ----->>>>" + line);
						n = new Node_Nslookup(line);						
					}
					else
						Node_Nslookup.get(line);
					
				}
				catch(Exception ee)
				{
					driver.eop_loop(myClassName, "import_nslookup_data_file", ee, count);
					continue;
				}
				
				++count;				
			}
			
			try	{	br.close();}catch(Exception e){}
			
			int after_size = Node_Nslookup.cache_nslookup_FOUND.size();
			
			driver.directive("Import nslookup file complete. Number lines read: [" + count + "]. Number entries added to cache: [" + (after_size - before_size) + "]");
			
			process_import_interrupt = true;
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "import_nslookup_data_file", e);
		}
		
		process_import_interrupt = true;
		return false;
	}
	
	public String get_json_formatted(boolean include_braces)
	{
		try
		{
			value = "\"nslookup_request\":\"" + request   + "\", "
					+ "\"nslookup_server\":\"" + server   + "\", "
					+ "\"nslookup_address_1\":\"" + address_1   + "\", "
					+ "\"nslookup_name\":\"" + name   + "\", "
					+ "\"nslookup_address_2\":\"" + address_2   + "\", "
					+ "\"nslookup_ipv4_first\":\"" + ipv4_first   + "\", "
					+ "\"nslookup_ipv6_first\":\"" + ipv6_first   + "\", "
					+ "\"nslookup_ipv4\":\"" + ipv4   + "\", "					
					+ "\"nslookup_ipv6\":\"" + ipv6   + "\", "
					+ "\"nslookup_last_retrieved\":\"" + last_retrieved   + "\", "
					+ "\"nslookup_last_update_time\":" + last_update_time   + ", "
					+ "\"nslookup_authoritative\":\"" + authoritative   + "\", "
					+ "\"nslookup_source\":\"" + SOURCE + "\"";
			
			//":"America/Los_Angeles","":47.5716,"":-122.3327,"":819}
			if(include_braces)
			{
				return "{" + value + "}";	
			}
			
			else 
				return  value;
						
								
			
			
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_json", e);
		}
		
		return "{}";
	}
	
	public String get_map_details()
	{
		try
		{
			value =   "<br><b>nslookup_request: </b>" + request
					+ "<br><b>nslookup_server: </b>" + server
					+ "<br><b>nslookup_address_1: </b>" + address_1
					+ "<br><b>nslookup_name: </b>" + name
					+ "<br><b>nslookup_address_2: </b>" + address_2
					+ "<br><b>nslookup_ipv4_first: </b>" + ipv4_first
					+ "<br><b>nslookup_ipv6_first: </b>" + ipv6_first
					+ "<br><b>nslookup_ipv4: </b>" + ipv4
					+ "<br><b>nslookup_ipv6: </b>" + ipv6
					+ "<br><b>nslookup_last_retrieved: </b> " + last_retrieved
					+ "<br><b>nslookup_last_update_time</b>: " + last_update_time
					+ "<br><b>nslookup_authoritative:</b> " + authoritative
					+ "<br><b>nslookup_source:</b> " + SOURCE + "<br>";
			
			return  value;
						
								
			
			
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_map_details", e);
		}
		
		return "{}";
	}
	
	
	public static boolean sop(String out)
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
	
	
	public String get_details(boolean include_header, String token, String delimiter)
	{
		try
		{
			
			if(include_header)
			{
				value =   "nslookup_request" + token + " " +request + delimiter
						+ "nslookup_server" + token + " " +server + delimiter
						+ "nslookup_address_1" + token + " " +address_1 + delimiter
						+ "nslookup_name" + token + " " +name + delimiter
						+ "nslookup_address_2" + token + " " +address_2 + delimiter
						+ "nslookup_ipv4_first" + token + " " +ipv4_first + delimiter
						+ "nslookup_ipv6_first" + token + " " +ipv6_first + delimiter
						+ "nslookup_ipv4" + token + " " +ipv4 + delimiter
						+ "nslookup_ipv6" + token + " " +ipv6 + delimiter
						+ "nslookup_last_retrieved: " + last_retrieved + delimiter
						+ "nslookup_last_update_time: " + last_update_time + delimiter
						+ "nslookup_authoritative: " + authoritative + delimiter
						+ "nslookup_source: " + SOURCE;
			}
			
			else
			{
				value =   request + delimiter+
						server + delimiter+
						address_1 + delimiter+
						name + delimiter+
						address_2 + delimiter+
						ipv4_first + delimiter+
						ipv6_first + delimiter+
						ipv4 + delimiter+
						ipv6 + delimiter+
						last_retrieved + delimiter+
						last_update_time + delimiter+
						authoritative + delimiter+
						SOURCE;
			}
			
			
			return  value;
						
								
			
			
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_details", e);
		}
		
		return "{}";
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}