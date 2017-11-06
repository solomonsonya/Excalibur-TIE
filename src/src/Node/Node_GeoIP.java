package Node;

/**
 * @author Solomon Sonya
 */

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.*;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;
import java.text.*;
import java.util.*;

import Driver.Driver;
import Driver.Log;

public class Node_GeoIP 
{
	public static final String myClassName = "Node_GeoIP";
	public static volatile Driver driver = new Driver();
	
	public static final String geo_ip_request_1 = "http://freegeoip.net/json/";
	public static final int max_geo_requests_per_hour = 15000;
	public static volatile int geo_requests_per_hour_count = 0;

	
	
	public static volatile TreeMap<String, Node_GeoIP> cache_FOUND = new TreeMap<String, Node_GeoIP>();
	public static volatile TreeMap<String, Node_GeoIP> cache_NOT_FOUND = new TreeMap<String, Node_GeoIP>();
	
	public volatile Node_Nslookup node_nslookup = null;
	
	public volatile Log log_geo_found = null;
	public volatile Log log_geo_not_found = null;
	
	public volatile static boolean debug = false;
	
	public volatile String details = "";
	
	
	public volatile String value = "", href = "";
	
	public static volatile boolean OVERRIDE_STORE_NEW_RESULTS = true;
	
	public static final String format_JSON = "json";
	public static final String format_CSV = "csv";
	public static final String format_CSV_WITHOUT_HEADER = "csv_without_header";
	public static final String format_LIST = "list";
	public static final String format_LIST_WITHOUT_HEADER = "list_without_header";
	
	public static volatile boolean auto_resolve_if_not_found_in_cache = true;

	public static final int resolution_timeout_seconds = 30;
	
	public static volatile boolean EMBED_MAP = true;
	
	public volatile boolean parse_complete = false, determined_self_location = false;
	//{"ip":"98.99.180.199","country_code":"US","country_name":"United States","region_code":"WA","region_name":"Washington","city":"Seattle"
	//,"zip_code":"98134","time_zone":"America/Los_Angeles","latitude":47.5716,"longitude":-122.3327,"metro_code":819}
	
	public volatile String request = "";
	public volatile String ip = "";
	public volatile String country_code = "";
	public volatile String country_name = "";
	public volatile String region_state_code = "";
	public volatile String region_state_name = "";
	public volatile String city = "";
	public volatile String zip_code = "";
	public volatile String time_zone = "";
	public volatile String latitude = "";
	public volatile String longitude = "";
	public volatile String metro_area_code = "";
	
	public volatile String json_original = "";
	public volatile String json_formatted = "";
	
	public static final String SOURCE = Driver.NAME + "_" + "GEOLOOKUP";
	
	public volatile String authoritative = driver.authoritative_not_found;
	
	public long last_update_time = System.currentTimeMillis();
	public volatile String timeStamp = new SimpleDateFormat("yyyy-MM-dd-HH:mm.ss").format(new Date());
	public volatile String last_retrieved = new SimpleDateFormat("yyyy-MM-dd-HH:mm.ss").format(new Date());

	public static volatile boolean perform_nslookup = false;
	public static volatile boolean perform_whois = true;
	
	public static final String BLANK_ROW = " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t" + " \t";
	
	public Node_GeoIP()
	{
		try
		{
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public Node_GeoIP(String REQUEST, boolean FORCE_NEW_RESOLUTION_IF_ALREADY_EXISTS_IN_CACHE)
	{
		try
		{
			if(REQUEST != null && REQUEST.trim().equals("") && FORCE_NEW_RESOLUTION_IF_ALREADY_EXISTS_IN_CACHE)
			{
				driver.sop("Determining SELF location now...");
				determined_self_location = true;
			}
			
			request = REQUEST.trim();
			json_original = lookup(request, FORCE_NEW_RESOLUTION_IF_ALREADY_EXISTS_IN_CACHE);
			parse_complete = parse(json_original, OVERRIDE_STORE_NEW_RESULTS);
			
			if(parse_complete && determined_self_location)
			{
				//cache_FOUND.put("me", this);
				//cache_FOUND.put("ME", this);
				//cache_FOUND.put("Me", this);
			}
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
		
	}
	
	public Node_GeoIP(String REQUEST, String json)
	{
		try
		{
			json_original = json;
			request = REQUEST.trim();
			parse_complete = parse(json, OVERRIDE_STORE_NEW_RESULTS);
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 3", e);
		}
	}
	
	public static boolean print_domains(String domain)
	{
		try
		{
			if(cache_FOUND.isEmpty())
			{
				driver.sop(" * * * ERROR! NO CONTENTS POPULATED IN CACHE YET! Display help for further options...");
				return false;
			}
						
			
			LinkedList<Node_GeoIP> list = new LinkedList<Node_GeoIP>(Node_GeoIP.cache_FOUND.values());
			
			if(list == null || list.isEmpty())
			{
				driver.sop(" * ERROR!!! NO CONTENTS POPULATED IN RESOLUTION LIST YET! No data to print yet...");
				return false;
			}
			
			
			int match = 0;
			Node_GeoIP node = null;
			for(int i = 0; i < list.size(); i++)
			{
				try
				{
					node = list.get(i);
					
					if(domain == null || domain.trim().equals(""))
					{
						driver.sop(node.request + ", " + node.ip);
						++match;
					}
					else if(node.request.toLowerCase().endsWith(domain.toLowerCase().trim()) || node.ip.toLowerCase().endsWith(domain.toLowerCase().trim()))
					{
						driver.sop(node.request + ", " + node.ip);
						++match;
					}
						
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "print_domain", e, i);
					continue;
				}
			}
			
			if(match < 1)
				driver.sop("NO RESULTS MATCH YOUR QUERY!");
			else
				driver.sop("\n* * * Complete. " + match + " result(s) returned.");
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_domain", e);
		}
		
		return false;
	}
	
	public static Node_GeoIP resolve(String req, boolean force_new_resolution_if_already_exists_in_cache)
	{
		try
		{
			//
			//check cache
			//
			if(!force_new_resolution_if_already_exists_in_cache && cache_FOUND.containsKey(req))
				return cache_FOUND.get(req);
			
			//otherwise, resolve the address now...
			Node_GeoIP node = new Node_GeoIP(req, force_new_resolution_if_already_exists_in_cache);
			
			if(node.parse_complete)
				return node;
			
			else
				return null;
			
		}
		
		
		
		catch(Exception e)
		{
			driver.eop(myClassName, "resolve", e);
		}
		
		return null;
	}
	
	public static boolean print_cache_not_found(String domain)
	{
		try
		{
			if(cache_NOT_FOUND.isEmpty())
			{
				driver.sop(" * * * ERROR!! NO CONTENTS POPULATED IN CACHE YET! Display help for further options...");
				return false;
			}
						
			
			LinkedList<Node_GeoIP> list = new LinkedList<Node_GeoIP>(Node_GeoIP.cache_NOT_FOUND.values());
			
			if(list == null || list.isEmpty())
			{
				driver.sop(" * ERROR!! NO CONTENTS POPULATED IN RESOLUTION LIST YET! No data to print yet...");
				return false;
			}
			
			
			Node_GeoIP node = null;
			for(int i = 0; i < list.size(); i++)
			{
				try
				{
					node = list.get(i);
					
					driver.directive(node.request);
						
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "print_cache_not_found", e, i);
					continue;
				}
			}
			
			
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_cache_not_found", e);
		}
		
		return false;
	}
	
	public static boolean print_cache(String domain)
	{
		try
		{
			if(cache_FOUND.isEmpty())
			{
				driver.sop(" * * * ERROR! NO CONTENTS POPULATED IN CACHE YET! Display help for further options...");
				return false;
			}
						
			
			LinkedList<Node_GeoIP> list = new LinkedList<Node_GeoIP>(Node_GeoIP.cache_FOUND.values());
			
			if(list == null || list.isEmpty())
			{
				driver.sop(" * ERROR!!! NO CONTENTS POPULATED IN RESOLUTION LIST YET! No data to print yet...");
				return false;
			}
			
			
			int match = 0;
			Node_GeoIP node = null;
			for(int i = 0; i < list.size(); i++)
			{
				try
				{
					node = list.get(i);
					
					if(domain == null || domain.trim().equals(""))
					{
						driver.sop(node.get_json_formatted(null));
						++match;
					}
					else if(node.request.toLowerCase().endsWith(domain.toLowerCase().trim()) || node.ip.toLowerCase().endsWith(domain.toLowerCase().trim()))
					{
						driver.sop(node.get_json_formatted(null));
						++match;
					}
						
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "print_cache", e, i);
					continue;
				}
			}
			
			if(match < 1)
				driver.sop("NO RESULTS MATCH YOUR QUERY!");
			else
				driver.sop("\n* * * Complete. " + match + " result(s) returned.");
			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "print_cache", e);
		}
		
		return false;
	}
	
	public String lookup(String req, boolean FORCE_NEW_RESOLUTION_IF_ALREADY_EXISTS_IN_CACHE)
	{
		BufferedReader br = null;
		
		try
		{
			
			if((req == null || req.trim().equals("")) && !FORCE_NEW_RESOLUTION_IF_ALREADY_EXISTS_IN_CACHE)
				return "{}";
			
			req = req.trim();
			
			if(!FORCE_NEW_RESOLUTION_IF_ALREADY_EXISTS_IN_CACHE && cache_FOUND.containsKey(req))
				return cache_FOUND.get(req).get_json_formatted(null);
			//driver.sop("resolving -->" + req);
			
			//
			//punt if we've exceeded our count att
			//
			if(geo_requests_per_hour_count++ > max_geo_requests_per_hour)
				return null;
			
			//
			//resolve
			//
			URL url = new URL(geo_ip_request_1 + req);
			URLConnection conn = url.openConnection();
			conn.setConnectTimeout(resolution_timeout_seconds*1000);
			conn.setReadTimeout(resolution_timeout_seconds*1000);
			br = new BufferedReader(new InputStreamReader(conn.getInputStream()));
			String in = "", response = "";
			
			while((in = br.readLine()) != null)
			{								
				response = response + in.trim();
			}
			
			try	{	br.close();	} catch(Exception e){}
			
			
			//
			//process response of address!
			//
			return response;			
		}
		
		catch(SocketTimeoutException timeout)
		{
			driver.directive("\n//\n//PUNT! Request for [" + req + "] timeout before a response could be received. I must terminate this routine...\n//\n");
			try	{	br.close();	} catch(Exception e){}
			
			driver.log("user, Request for [" + req + "] encountered a timeout after " + resolution_timeout_seconds + " seconds of inactivity from the distant resolution server");
			
			json_original = "404 Request Not Found for address [" + req + "]";
		}
		
		catch(IOException ioe)
		{
			json_original = "404 Request Not Found for address [" + req + "]";
		}
		/*catch(FileNotFoundException fne)
		{
			json_original = "404 Request Not Found for address [" + req + "]";
												
		}*/
		catch(Exception e)
		{
			driver.eop(myClassName, "resolve", e);
		}
		
		return json_original;
	}
	
	public boolean update_nslookup()
	{
		try
		{
			if(node_nslookup == null || !node_nslookup.parse_complete || node_nslookup.address_2 == null || node_nslookup.address_2.trim().equals(""))
				node_nslookup = Node_Nslookup.get(request);			
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_nslookup", e);
		}
		
		return false;
	}
	
	public boolean update_whois()
	{
		try
		{
			/*if(node_whois == null || !node_whois.is_valid_whois_retrieval || node_whois.domain_name == null || node_whois.domain_name.trim().equals(""))
				node_whois = Node_Whois.get(request, true, false);	*/		
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "update_whois", e);
		}
		
		return false;
	}
	
	
	public boolean parse(String json, boolean override_store_new_results)
	{
		try
		{
			if(json == null || json.trim().equals(""))
				return false;
			
			json = json.trim();
			
			String [] tuples = null;
			
			//
			//this could also be loaded from a log file. ideally, the user chooses the correct log file that begins with "{"request":"google.it", "ip":...etc, but the user could choose the wrong log file
			//in this case, update the line based on the file chosen by the user
			//
			/*if(!json.trim().startsWith("\\{"))
			{
				tuples = json.split(",");
				if(tuples != null && tuples.length > 2 && tuples[2].trim().startsWith("\\{"))
				{
					System.out.println("FOUND! incorrect json received to parse. Attempting to update format to parse beginning at index 2 instead of index 0...");
					driver.sop("FOUND! incorrect json received to parse. Attempting to update format to parse beginning at index 2 instead of index 0...");
					json = tuples[2];
					for(int i = 3; i < tuples.length; i++)
					{
						try
						{
							json = json + "," + tuples[i];				
						}
						catch(Exception e)
						{
							driver.eop_loop(myClassName, "parse", e, i);
							continue;
						}
					}
				}
			}*/
			
			//{"ip":"98.99.180.199","country_code":"US","country_name":"United States","region_code":"WA","region_name":"Washington","city":"Seattle","zip_code":"98134","time_zone":"America/Los_Angeles","latitude":47.5716,"longitude":-122.3327,"metro_code":819}
			//I will just parse the json here in lieu of requiring an additional json package...
			json = json.replaceAll("\"", "");
			json = json.replaceAll("\\{", "");
			json = json.replaceAll("\\}", "");
			json = json.trim();
			
			tuples = json.split(",");
			
			//now split by the key, value pair
			String [] arr = null;
			for(int i = 0; tuples != null && i < tuples.length; i++)
			{
				try
				{
					//potentially ipv6
					if(tuples[i].startsWith("ip") && tuples[i].contains("::"))
					{
						ip = tuples[i].replaceFirst("ip:", "");
						continue;
					}
					
					arr = tuples[i].split(":");
					
					//note, for now, this does not handle IPv6 addresses that are returned!
					
					if(arr.length > 1 && arr[0].toLowerCase().trim().equals("request"))
						request = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("ip"))
						ip = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("country_code"))
						country_code = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("country_name"))
						country_name = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("region_code"))
						region_state_code = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("region_name"))
						region_state_name = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("city"))
						city = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("zip_code"))
						zip_code = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("time_zone"))
						time_zone = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("latitude"))
						latitude = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("longitude"))
						longitude = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("metro_code"))
						metro_area_code = arr[1].trim();
					else if(arr.length > 1 && arr[0].toLowerCase().trim().equals("last_retrieved"))
						last_retrieved = arr[1].trim();
					else if(json.contains("nslookup_request")) //don't trigger on an nslookup entry
						continue;
					else
						driver.sop("UNKNOWN TUPLE VALUE received in " + myClassName + ". Tuple [" + arr[0] + " value " + arr[1] + ". full json: " + json + ". index: " + i);
					
				}
				catch(ArrayIndexOutOfBoundsException ar)
				{
					//likely caused from ipv6... bcs everything else should be ready to handle each json object... concat to the ipv6
					//ip = ip + ":" + arr[0].trim();
				}
				catch(Exception e)
				{
					driver.eop_loop(myClassName, "parse", e, i);
					continue;
				}
			}
			
			//
			//nslookup
			//
			if(json.toLowerCase().contains("nslookup_request") && json.toLowerCase().contains("nslookup_server") && json.toLowerCase().contains("nslookup_address_1") && json.toLowerCase().contains("nslookup_name") && json.toLowerCase().contains("nslookup_address_2"))
			{
				//parse this request
				if(node_nslookup == null || !node_nslookup.parse_complete)
					node_nslookup = new Node_Nslookup();
				
				try	{	node_nslookup.parse_import_file(json);	}	catch(Exception e){driver.directive("ERROR TRYING TO PARSE NSLOOKUP FOR REQUEST [" + json + "]");	}
			}
			
			//
			//whois
			//
			if(json.toLowerCase().contains("whois_domain_name") && json.toLowerCase().contains("whois_registrar") && json.toLowerCase().contains("whois_sponsoring_registrar_iana_id"))
			{
				//parse this request
				/*if(node_whois == null || !node_whois.is_valid_whois_retrieval)
					node_whois = new Node_Whois();
				
				try	{	node_whois.parse_import_file(json);	}	catch(Exception e){driver.directive("ERROR TRYING TO PARSE WHOIS FOR REQUEST [" + json + "]");	}*/
			}
			
			//
			//PARSE COMPLETE
			//
			if(ip != null && !ip.trim().equals("") && latitude != null && !latitude.trim().equals("") && longitude != null && !longitude.trim().equals(""))
			{
				parse_complete = true;
				authoritative = driver.authoritative_found;
				
				if(request == null || request.trim().equals(""))
					request = ip;
				
				if(ip == null || ip.trim().equals(""))
					ip = request;
				
				//
				//nslookup
				//
				if(perform_nslookup && node_nslookup == null)
					node_nslookup = Node_Nslookup.get(request);
				
				//
				//whois
				//
				/*if(perform_whois && node_whois == null)
					node_whois = Node_Whois.get(request, false, false);*/
				
				//
				//cache
				//
				if(cache_FOUND.containsKey(request))
				{
					if(override_store_new_results)
					{
						/*if(node_nslookup == null)
							node_nslookup = Node_Nslookup.get(request);*/
						
						driver.sop("Previous contents of cache for request [" + request + "] has been updated from " + cache_FOUND.get(request).get_json_formatted(null) + " to -->" +  this.get_json_formatted(null));
						cache_FOUND.put(request, this);
												
						
						if(log_geo_found == null)
							log_geo_found = new Log("geo_found",  "log_geo_found", 250, 999999999);
						
						log_geo_found.log(this.get_json_formatted(null));
																		
					}
				}
				
				else//not in the cache, add it!
				{
					/*if(node_nslookup == null)
						node_nslookup = Node_Nslookup.get(request);*/
					
					if(debug)
						driver.sop("Adding to the [cache] --> " + this.get_json_formatted(null));
										
					if(log_geo_found == null)
						log_geo_found = new Log("geo_found",  "log_geo_found", 250, 999999999);
					
					log_geo_found.log(this.get_json_formatted(null));
					
					cache_FOUND.put(request, this);					
				}
				
				/*if(!cache_FOUND.containsKey(request))
				{
					driver.sop("Adding to the [cache] --> " + this.get_json_formatted());
					cache_FOUND.put(request, this);
					driver.log_resolution(this.get_json_formatted());
				}*/
			}
			else
			{
				/*if(!cache_NOT_FOUND.containsKey(request))
				{
					cache_NOT_FOUND.put(this.request, this);
					driver.log_request_not_found(request);
				}*/
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "parse", e);
			e.printStackTrace(System.out);
		}
		
		try
		{
			if(!parse_complete)
			{
				if(!cache_NOT_FOUND.containsKey(request))
				{
					cache_NOT_FOUND.put(this.request, this);
					
					
					if(log_geo_not_found == null)
						log_geo_not_found = new Log("geo_not_found",  "log_geo_not_found", 250, 999999999);
					
					log_geo_not_found.log(request);
				}
			}
		} catch(Exception ee) {driver.eop(myClassName, "parse", ee);}
		
		return parse_complete;
		
		
	}
	
	public String get_json_original()
	{
		try
		{
			return json_original;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_json_original", e);
		}
		
		return "{}";
	}
	
	public String get_location()
	{
		try
		{
			return "IP: [" + ip + "] Country: [" + country_name + "] State: [" +  region_state_name + "] City: [" + city + "] ZipCode: [" + zip_code + "] Latitude: [" + latitude + "] Longitude: [" + longitude + "] Metro Code: [" + metro_area_code + "]" ;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_location", e);
		}
		
		return get_json_formatted(null);
	}
	
	public String get_json_formatted(String override_request_address)
	{
		try
		{
			//":"America/Los_Angeles","":47.5716,"":-122.3327,"":819}
			value =  "{";
					
					if(override_request_address != null && !override_request_address.trim().equals(""))
						value = value + "\"request\":\"" + override_request_address   + "\",";
					else
						value = value + "\"request\":\"" + request   + "\",";
					
					
					
					
					value = value + "\"ip\":\"" + ip   + "\","
					+ "\"country_code\":\"" + country_code + "\","
					+ "\"country_name\":\"" + country_name + "\","
					+ "\"region_code\":\"" + region_state_code + "\","
					+ "\"region_name\":\"" + region_state_name + "\","
					+ "\"city\":\"" + city + "\","
					+ "\"zip_code\":\"" + zip_code + "\","
					+ "\"time_zone\":\"" + time_zone + "\","
					+ "\"latitude\":" + latitude + ","
					+ "\"longitude\":" + longitude + ","
					+ "\"metro_code\":" + metro_area_code + ","
					+ "\"last_update_time\":" + last_update_time + ","
					+ "\"last_retrieved\":\"" + timeStamp + "\","
					+ "\"source\":\"" + SOURCE + "\","
					+ "\"authoritative\":\"" + authoritative + "\"";
					
					if(node_nslookup != null)
					{
						value = value + ", " + node_nslookup.get_json_formatted(false);
					}
					
					/*if(node_whois != null && node_whois.is_valid_whois_retrieval)
					{
						value = value + ", " + node_whois.get_json_formatted("whois_", false);
					}*/
					
					
				value = value + "}";		
				
				return value;					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_json", e);
		}
		
		return "{}";
	}
	
	public boolean isLatLonLoaded()
	{
		try
		{
			if(latitude != null && !latitude.trim().equals("") && longitude != null && !longitude.trim().equals(""))
				return true;			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "isLatLonLoaded", e);
		}
		
		return false;
	}
	
	public String getGoogleMapEmbedCode(int width, int height)
	{
		try
		{
			if(width < 1 && height < 1)
				return "<iframe src=\"http://maps.google.com/maps?q=" + latitude + "," + longitude + "&z=3&output=embed\"></iframe>";
			
			return "<iframe width=\"" + width + "\" height=\"" + height + "\" src=\"http://maps.google.com/maps?q=" + latitude + "," + longitude + "&z=3&output=embed\"></iframe>";
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getGoogleMapEmbedCode", e);
		}
		
		return "";
	}
	
	public String get_web_HTML_formatted(String node_requestor_ip_address, Node_GeoIP ndeRequestor)
	{
		try
		{						
			value = "";
			//value = HTML_HEADER_MSG(node_requestor_ip_address, ndeRequestor);
			
			value = value + "<br><b>GEO</b><hr>";
			
			value = value + "<b>request: </b>"  + request   
					
					+ "<br><b>ip: </b>"  + ip   
					+ "<br><b>country_code: </b>"  + country_code 
					+ "<br><b>country_name: </b>"  + country_name 
					+ "<br><b>region_code: </b>"  + region_state_code 
					+ "<br><b>region_name: </b>"  + region_state_name 
					+ "<br><b>city: </b>"  + city 
					+ "<br><b>zip_code: </b>"  + zip_code 
					+ "<br><b>time_zone: </b>"  + time_zone 
					+ "<br><b>latitude: </b>" + latitude 
					+ "<br><b>longitude: </b>" + longitude 
					+ "<br><b>metro_code: </b>" + metro_area_code 
					+ "<br><b>last_update_time: </b>" + last_update_time 
					+ "<br><b>last_retrieved: </b>"  + timeStamp 
					+ "<br><b>source: </b>"  + SOURCE 
					+ "<br><b>authoritative: </b>"  + authoritative;
					
					if(latitude != null && !latitude.trim().equals("") && longitude != null && !longitude.trim().equals(""))
						value = value +  "<br><a href=\"http://maps.google.com/maps?q=" + latitude + "," + longitude + "\"> View on Google Map </a>";
			
					
					
			//https://www.google.com/maps/preview/@-15.623037,18.388672,8z
			//http://maps.google.com/maps?q=39.9289,116.3883

				
			
			/*if(node_nslookup != null)
			{
				value = value + "<br><br><b>NSLOOKUP</b><hr>" + node_nslookup.get_map_details();
			}*/
			
			/*if(node_whois != null && !node_whois.LIST_WHOIS_DATA.isEmpty() && node_whois.data_populated)
			{
				value = value + "<br><br><b>WHOIS</b><hr>" + node_whois.get_web_formatted();
			}*/
			
			//
			//embed map
			//
			if(EMBED_MAP && latitude != null && !latitude.trim().equals("") && longitude != null && !longitude.trim().equals(""))
				value = value + "<br><br><br><b>GOOGLE MAP</b>      [" + this.request + "]  " + this.getCountryData(",") + "<hr>" + this.getGoogleMapEmbedCode(900, 600) + "<br><br>";
			return value;
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_web_HTML_formatted", e);
		}
		
		try	{	return get_json_formatted(null);	}	catch(Exception ee){driver.eop(myClassName, "exception of get_web_HTML_formatted", ee);	}
		
		return "{}";
	}
	
	public String HTML_HEADER_MSG(String value_to_href, Node_GeoIP ndeRequestor)
	{
		try
		{
			if(value_to_href == null)
				return "";
			
			if(ndeRequestor == null)
				href = "<b> " + value_to_href + " </b>";
			else
				href = "<a href=\"http://maps.google.com/maps?q=" + ndeRequestor.latitude + "," + ndeRequestor.longitude + "\"> " + value_to_href + " </a>";
			
			value = ("<html><b>" + driver.FULL_NAME + " by Solomon Sonya @Carpenter1010" + " " + driver.get_time_stamp() + "</b> - Your Connection IP: [" + href + "]<br><br>");
			
			return value;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "HTML_HEADER_MSG", e);
		}
		
		return "{{}}<br><br>";
	}
	
	public String get_HTML_WELCOME_MESSAGE(String value_to_href)
	{
		try
		{		
			value = HTML_HEADER_MSG(value_to_href, this);
			
			if(latitude != null && !latitude.trim().equals("") && longitude != null && !longitude.trim().equals(""))
				value = value + "<b><u>[YOUR CONNECTION]:</b></u>   " +  "<a href=\"http://maps.google.com/maps?q=" + latitude + "," + longitude + "\"> " + ip + " </a>";
			
			else//(latitude == null || latitude.trim().equals("") || longitude == null || longitude.equals(""))
				value = value + "<b><u>[YOUR CONNECTION]:</b></u> " + value_to_href + "<br><hr><br> ";
			
			value = value + "<br><br>" + get_web_HTML_formatted(null, null);
					
			
			return value;		
					
			
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_HTML_WELCOME_MESSAGE", e);
		}
		
		try	{	return get_json_formatted(null);	}	catch(Exception ee){driver.eop(myClassName, "get_HTML_WELCOME_MESSAGE PART II", ee);	}
		
		return "{}";
	}
	
	public String getCountryData(String delimiter)
	{
		try
		{
			this.value = "";
			
			if(this.country_name != null && !this.country_name.trim().equals(""))
				value = country_name;
			
			if(this.region_state_name != null && !this.region_state_name.trim().equals(""))
			{
				if(value.trim().equals(""))
					value = region_state_name;
				else
					value = value + delimiter + " " + region_state_name;
			}
			
			if(this.city != null && !this.city.trim().equals(""))
			{
				if(value.trim().equals(""))
					value = city;
				else
					value = value + delimiter + " " + city;
			}
			
			if(this.zip_code != null && !this.zip_code.trim().equals(""))
			{
				if(value.trim().equals(""))
					value = zip_code;
				else
					value = value + delimiter + " " + zip_code;
			}
			
			return value;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "getCountryData", e);
		}
		
		return "";
	}
	
	public String get_404()
	{
		try
		{
			return "404 Not Found - \"" + request + "\" - last updated: " + this.timeStamp;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_404", e);
		}
		
		return "404 Address not found";
	}
	
	public String get_csv(boolean include_header, String token)
	{
		try
		{
			if(token == null)
				token = ":";
			
			if(include_header)			
				return  "request" + token  + request   + " ,"
						+ "ip" + token  + ip   + " ,"
						+ "country_code" + token  + country_code + " ,"
						+ "country_name" + token  + country_name + " ,"
						+ "region_code" + token  + region_state_code + " ,"
						+ "region_name" + token  + region_state_name + " ,"
						+ "city" + token  + city + " ,"
						+ "zip_code" + token  + zip_code + " ,"
						+ "time_zone" + token  + time_zone + " ,"
						+ "latitude" + token  + latitude + " ,"
						+ "longitude" + token  + longitude + " ,"
						+ "metro_code" + token  + metro_area_code + " ,"		
						+ "last_retrieved" + token + timeStamp

						;	
			
			//
			//otw
			//
			return  request   + " ,"
			+ ip   + " ,"
			+ country_code + " ,"
			+ country_name + " ,"
			+ region_state_code + " ,"
			+ region_state_name + " ,"
			+ city + " ,"
			+ zip_code + " ,"
			+ time_zone + " ,"
			+ latitude + " ,"
			+ longitude + " ,"
			+ metro_area_code + " ,"
			+ timeStamp
			;	
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_csv", e);
		}
		
		return "{}";
	}
	
	
	
	
	public String get_details(boolean include_header, String token, String delimiter)
	{
		try
		{
			if(token == null)
				token = ":";
			
			if(include_header)			
				return  "geolookup_request" + token  + request      + " " + delimiter
						+ "geolookup_ip" + token  + ip      + " " + delimiter 
						+ "geolookup_country_code" + token  + country_code    + " " + delimiter 
						+ "geolookup_country_name" + token  + country_name    + " " + delimiter 
						+ "geolookup_region_code" + token  + region_state_code    + " " + delimiter 
						+ "geolookup_region_name" + token  + region_state_name    + " " + delimiter 
						+ "geolookup_city" + token  + city    + " " + delimiter 
						+ "geolookup_zip_code" + token  + zip_code    + " " + delimiter 
						+ "geolookup_time_zone" + token  + time_zone   + " " + delimiter 
						+ "geolookup_latitude" + token  + latitude    + " " + delimiter 
						+ "geolookup_longitude" + token  + longitude    + " " + delimiter 
						+ "geolookup_metro_code" + token  + metro_area_code    + " " + delimiter
						+ "geolookup_last_updated" + token + last_update_time + " " + delimiter
						+ "geolookup_last_retrieved" + token + timeStamp + " " + delimiter						
						+ "geolookup_source" + token + SOURCE + " " + delimiter
						+ "geolookup_authoritative" + token +  this.authoritative;
						
			

						;	
			
			//
			//otw
			//
			return  request   + " " + delimiter
			+ ip   + " " + delimiter
			+ country_code + " " + delimiter
			+ country_name + " " + delimiter
			+ region_state_code + " " + delimiter
			+ region_state_name + " " + delimiter
			+ city + " " + delimiter
			+ zip_code + " " + delimiter
			+ time_zone + " " + delimiter
			+ latitude + " " + delimiter
			+ longitude + " " + delimiter
			+ metro_area_code + " " + delimiter
			+ this.last_update_time + " " + delimiter
			+ timeStamp + " " + delimiter
			+ SOURCE  + " " + delimiter
			+ this.authoritative
			;	
					
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "get_details", e);
		}
		
		return "{}";
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
}
