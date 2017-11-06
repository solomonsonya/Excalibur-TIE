/**
 * @author Solomon Sonya
 */


package Driver;

	
	/**
	 * @author Solomon Sonya
	 */

	import java.awt.Toolkit;
	

	import java.awt.datatransfer.Clipboard;
	import java.awt.datatransfer.StringSelection;
	import java.io.BufferedReader;
	import java.io.File;
	import java.io.InputStream;
	import java.io.InputStreamReader;
	import java.io.PrintWriter;
	import java.io.StringWriter;
	import java.net.Socket;
	import java.text.SimpleDateFormat;
	import java.util.Date;
	import java.util.LinkedList;
	import javax.swing.JFileChooser;
	import javax.swing.JOptionPane;
	import javax.swing.JPasswordField;
	import javax.swing.UIManager;

	public class Driver 
	{
		public static final String NAME = "Excalibur - LITE";
		public static final String VERSION = "1.004";
		public static final String FULL_NAME = NAME + " vrs " + VERSION;
		
		public static final String delimiter1 = "#####";
		public static final String delimiter2 = "~~~~~";
		public static final String delimiter3 = "````````";
		
		public static Time time = new Time();

		
		public static final String NOT_FOUND = "no results returned from selected query";
		
		
		public static volatile boolean displayed_welcome = false;
		public static final String myClassName = "Driver";
		
		
		public static volatile boolean output_enabled = true;
		
		
		
		public volatile String [] arr_ip = null;
		public volatile long value = 0;
		public static final int pow_256_3 = (int)Math.pow(256,3);
		public static final int pow_256_2 = (int)Math.pow(256,2);
		public static final int pow_256_1 = (int)Math.pow(256,1);
		public static final int pow_256_0 = (int)Math.pow(256,0);
		
		
		public static volatile boolean isWindows = false;
		public static volatile boolean isLinux = false;
		public static volatile boolean isMac = false;
		public static volatile boolean isSolarix = false;
		public static volatile String OS  = mapOS();
		
		public static volatile boolean populated_device_specification_lists = false;
		
		public static volatile SimpleDateFormat dateFormat_yyyy_mm_dd_hh_mm_ss = new SimpleDateFormat("yyyy-MM-dd-HHmm_ss");
		public static volatile Date dateTime_yyyy_mm_dd_hh_mm_ss = new Date(System.currentTimeMillis());
		public static volatile String TIME_OF_FIRST_START = getTime_Specified_Hyphenated_with_seconds(System.currentTimeMillis());

		
		public Driver()	{setLookAndFeel();  mapOS();}//Null constructor
		
		public volatile String string_list_search = "";
		
			
		public static String mapOS()
		{
			try
			{
				String os = System.getProperty("os.name").toLowerCase();
				
				if(os.contains("win"))
					isWindows = true;
				else if(os.contains("nix") || os.contains("nux") || os.contains("aix"))
					isLinux = true;
				else if(os.contains("mac"))
					isMac = true;
				else if(os.contains("sun"))
					isSolarix = true;
				
				
				
				return os;
			}
			
			catch(Exception e)
			{
				System.out.println("Exception determining OS version");
			}
			
			return "unknown";
			
		}
		
		public String normalize_domain_name(String lookup)	
		{	
			try	{	return get_domain_name(lookup);	}
			catch(Exception e){}
			return lookup;
		}
		
		public String get_domain_name(String lookup)
		{
			try
			{
				String [] arr = null;
				
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
				eop(myClassName, "normalize_lookup", e);
			}
			
			return lookup;
		}
		
		/**
		 * This method queries the user via JChooser to select a file
		 * 
		 * Examples: INPUT  FILE TO LOAD --> querySelectFile(false, "Please specify data set to import", JFileChooser.FILES_ONLY, false, false);
		 * Examples: OUTPUT FILE TO SAVE --> querySelectFile(true, "Please specify outfile location for " + x, JFileChooser.DIRECTORIES_ONLY, false, false)
		 */
		public  File querySelectFile(boolean openDialog, String dialogueTitle, int fileChooserSelectionMode, boolean thisLoadsCSV, boolean useFileFilter)
		{
			
			/**
			 * Drivers_Thread.fleCarrier_NetworkCommand = Drivers.querySelectFile(true, "Please Select the Carrier Image to hold the Steganographic command(s) and content", JFileChooser.FILES_ONLY, false, true);
				
				if(Drivers_Thread.fleCarrier_NetworkCommand == null)
				{
					this.jtfCarrierImage_Settings.setText("No Carrier Destination File Selected");
					this.jtfCarrierImage_Settings.setToolTipText("No Carrier Destination File Selected");
				}
				
				else//a good file was selected
				{
					this.jtfCarrierImage_Settings.setText(Drivers_Thread.fleCarrier_NetworkCommand.getCanonicalPath());
					jtfCarrierImage_Settings.setToolTipText(Drivers_Thread.fleCarrier_NetworkCommand.getCanonicalPath());
				}
			 */
			
			try
			{
				JFileChooser jfc = new JFileChooser(new File("."));
				jfc.setFileSelectionMode(fileChooserSelectionMode);
				jfc.setDialogTitle(dialogueTitle);
				//jfc.setMultiSelectionEnabled(enableMultipleFileSelection);
				
				if(thisLoadsCSV)
				{
					jfc.setFileFilter(new javax.swing.filechooser.FileFilter() 
					{
			            public boolean accept(File fle) 
			            {
			                //accept directories
			            	if(fle.isDirectory())
			                	return true;
			            	
			            	String strFleName = fle.getName().toLowerCase();
			                 
			                return strFleName.endsWith(".csv");
			              }
			   
			              public String getDescription() 
			              {
			                return "Comma Separated Values";
			              }
			              
			         });
					
				}
				
				/***************************************
				 * Filter for only Specified Formats
				 ***************************************/
				else if(useFileFilter)
				{
					jfc.setFileFilter(new javax.swing.filechooser.FileFilter() 
					{
			            public boolean accept(File fle) 
			            {
			            	String extension = "";
			            	
			                //accept directories
			            	if(fle.isDirectory())
			                	return true;
			            	
			            	if(fle == null)
			            		return false;
			            	
			            	if(fle != null && fle.exists() && getFileExtension(fle, false)!= null)
			            		extension = (getFileExtension(fle, false)).replace(".", "");//remove the "." if present
			            	
			            	/*if(lstAcceptableFileExtensionsForStego.contains(extension.toLowerCase()))
			            		return true;*/
			            	
			            	//else 
			            		return false;
			              }
			   
			              public String getDescription() 
			              {
			                return "Specific Formats";
			              }
			              
			         });
				}
				
				
				try
				{
					jfc.setCurrentDirectory(new File(".\\"));
				}catch(Exception e){}
				
				int selection = 0;
				
				if(openDialog)					
				{
					selection = jfc.showOpenDialog(null);
				}
				
				else
				{
					//selection = jfc.showDialog(null, "Save Now!"); <-- this code works too
					selection = jfc.showSaveDialog(null);
				}
						
				if(selection == JFileChooser.APPROVE_OPTION)//selected yes!
				{
					if(openDialog || (!openDialog && !thisLoadsCSV))
						return jfc.getSelectedFile();
					
					else
						return new File(jfc.getSelectedFile().getAbsolutePath() + ".csv");
				}
				
				//else fall through and return null;
			}
			
			catch(Exception e)
			{
				eop("querySelectFile", "Drivers", e);
				
			}
			
			return null;
		}
		
		
		
		
		
		public  String getFileExtension(File fle, boolean removeDot_Preceeding_Extension)
		{
			try
			{
				if(fle != null)
				{
					if(removeDot_Preceeding_Extension)
						return (fle.toString().substring(fle.toString().lastIndexOf(".") + 1));
						
					//some files do not have extensions, in such cases, SNSCat may seem to be crashing. therefore check if the file contains a "." at the end, if not, return what we have
					if(!fle.toString().contains(".") || fle.toString().lastIndexOf(".") < 0 )
					{
						try
						{
							return (fle.toString().substring(fle.toString().lastIndexOf(System.getProperty("file.separator"))));
						}
						catch(Exception e)
						{
							return " ";
						}
					}
					
					return (fle.toString().substring(fle.toString().lastIndexOf(".")));
				}
				
			}
			catch(NullPointerException npe)
			{
				sop("NullPointerException caught in getFileExtension_ByteArray mtd in Drivers.  This seems to be a sporadic error, called when user first attempts to view the files in a directory. This does not affect funtionality of program.  Dismissing error...");
			}
			catch(Exception e)
			{
				eop( "getFileExtension", "Drivers",e);
				
			}
			
			return null;
		}
		
		public File get_unique_file_name(File directory, String name, String extension)
		{
			try
			{
				File fle = null;
				
				if(directory.getCanonicalPath().trim().endsWith(File.separator))
					fle = new File(directory.getCanonicalPath().trim() + name.trim() + extension);
				else
					fle = new File(directory.getCanonicalPath().trim() + File.separator + name.trim() + extension);
				
				//check if the file name exists
				boolean unique_name = false;
				
				for(int i = 1; i < 1000000; i++)
				{
					//get out immediately if we have a unique file name
					if(fle != null && !fle.exists())
					{
						unique_name = true;
						return fle;
					}
					
					//otherwise, iterate to create the new file
					if(fle != null && fle.exists())
					{
						if(directory.getCanonicalPath().trim().endsWith(File.separator))
							fle = new File(directory.getCanonicalPath().trim() + name.trim() + "_" + i + extension);
						else
							fle = new File(directory.getCanonicalPath().trim() + File.separator + name.trim() + "_" + i + extension);
					}
				}
				
				//still made it here?!!!
				if(directory.getCanonicalPath().trim().endsWith(File.separator))
					fle = new File(directory.getCanonicalPath().trim() + name.trim() + "_" + System.currentTimeMillis() + extension);
				else
					fle = new File(directory.getCanonicalPath().trim() + File.separator + name.trim() + "_" + System.currentTimeMillis()  + extension);
				
							
				return fle;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_unique_file_name", e);
			}
			
			return null;
		}
		
		/**
		 * Provide the path starting with /
		 * 
		 * Wrap the Stream in a BufferedReader
		 * @param path
		 * @return
		 */
		public InputStream getFile_within_JAR(String path)
		{
			try
			{			
				return getClass().getResourceAsStream(path);			
			}
			
			catch(Exception e)
			{
				this.eop(myClassName, "getFile_within_JAR", e, false);
			}
			
			return null;
		}
		
		public static String exec(String cmd)
		{
			String response = "";
			try
			{
				Process proc = Runtime.getRuntime().exec(cmd);
				
				BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String line = "";
				
				while((line = br.readLine()) != null)
				{
					response = response + "\n" + line;
				}
			}
			catch(Exception e)
			{
				System.out.println("Exception caught in exec mtd in Driver");
			}
			
			return response;
		}
		
		public boolean print_linked_list(String msg, LinkedList<String> list)
		{
			try
			{
				this.directive(msg);
				
				if(list == null)
				{
					this.directive("PUNT! NO CONTENTS TO DISPLAY!");
					return true;
				}
				
				for(String element : list)
					this.directive("\t" + element);				
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "print_linked_list", e);
			}
			
			return false;
		}
		
		/**
		 * executes iwconfig <specific wlan> to determine if card is in monitor mode or not
		 * @param interface_name
		 * @return
		 */
		public boolean set_wireless_monitor_mode(String interface_name)
		{
			try
			{		
				if(interface_name == null || interface_name.trim().equals(""))
					return false;
				
				interface_name = interface_name.trim();
				
				boolean wlan_is_already_in_monitor_mode = false;
				
				//
				//First, determine if the wlan is already in monitor mode
				//
				//Process proc = Runtime.getRuntime().exec("sudo iwconfig " + interface_name);
				
				String [] cmd = new String [] {"/bin/bash", "-c", "iwconfig " + interface_name};
				Process proc = Runtime.getRuntime().exec(cmd);	
				
				BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
				String line = "";
				
				while((line = br.readLine()) != null)
				{	
									
					//reject if no wireless extension lines
					if(line.toLowerCase().trim().contains("no wireless extensions"))
					{
						this.directive("\nPUNT! No wireless extensions were found! I am unable to place interface [" + interface_name + "] into monitor mode...");
						try	{	br.close();} catch(Exception e){}
						return false;
					}
					
					//reject if error detected
					if(line.toLowerCase().trim().contains("no such device") || line.trim().contains("No such device"))
					{
						System.out.println("\nPUNT!! I am unable to place interface [" + interface_name + "] into monitor mode. It no longer appears to exist on this machine...");				
						try	{	br.close();} catch(Exception e){}
						return false;
					}
					
					//omit blank lines
					if(line.trim().equals(""))
						continue;
					
					//process legit line
					if(line.toLowerCase().trim().contains("mode") && line.toLowerCase().trim().contains("monitor"))
					{
						wlan_is_already_in_monitor_mode = true;
						break;
					}				
				}
				
				//close br to process
				try	{	br.close();} catch(Exception e){}
				
				//determine if necessary to place card into wireless mode. 
				//Note, it already would have punted out of here if wlan is invalid
				if(wlan_is_already_in_monitor_mode)
				{
					this.directive("Very good! Interface [" + interface_name + "] successfully appears to be in monitor mode :-)");
					return true;//specify we are success to have the wlan in monitor mode
				}
				
				this.directive("Attempting to set [" + interface_name + "] into monitor mode. Please standby...");
				
				//otw, set card into monitor mode
				boolean errors_detected_upon_setting_wlan_into_monitor_mode = false;
				
				String response = this.exec("sudo ifconfig " + interface_name + " down");
				response = response +  this.exec("sudo iwconfig " + interface_name + " mode monitor");
				response = response +  this.exec("sudo ifconfig " + interface_name + " up");
				
				if(response != null && response.toLowerCase().trim().contains("error"))
				{
					errors_detected_upon_setting_wlan_into_monitor_mode = true;
					this.directive("Errors noted --> " + response);
				}
				
				/*String cmd = "sudo ifconfig " + interface_name + " down && iwconfig " + interface_name + "  mode monitor && ifconfig " + interface_name + " up";
				this.directive("\nExecuting cmd: " + cmd);
				Process proc_iwconfig = Runtime.getRuntime().exec(cmd);
				
				//analyze output
				br = new BufferedReader(new InputStreamReader(proc_iwconfig.getInputStream()));
				line = "";
							
				while((line = br.readLine()) != null)
				{								
					//reject if no wireless extension lines
					if(line.toLowerCase().trim().contains("error"))
					{
						this.directive(" * * * ERROR detected while attempting to set interface [" + interface_name + " into monitor mode. Error Message --> \"" + line.trim() + "\"");
						errors_detected_upon_setting_wlan_into_monitor_mode = true;
					}	
					
					this.directive(line);
				}*/
				
				try	{ br.close();	}	catch(Exception e){}
				
				//
				//notify
				//
				if(errors_detected_upon_setting_wlan_into_monitor_mode)
				{
					this.directive("Errors were detected while attempting to place [" + interface_name + "] into monitor mode... functionality could be severly impacted...");
					return false;
				}
				else
				{
					this.directive("Process complete. If successful, interface [" + interface_name + "] should now be in monitor mode...");
					return true;
				}
					
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "set_wireless_monitor_mode", e);
			}
			
			return false;
		}
		
		public String convert_list_to_string(LinkedList<String> list, String token)
		{
			try
			{
				if(list == null || list.isEmpty())
					return "";
				
				String value = "";
				
				for(String element : list)
					value = value + element + token;
				
				if(value.trim().endsWith(token.trim()))
					value = value.substring(0, value.lastIndexOf(token.trim()));
				
				return value;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "convert_list_to_string", e);
			}
			
			return "";
		}
		
		/**
		 * return a list of interface names found on the computer. 
		 * 
		 * For linux machines, we assume the interface name starts the line and does not have any spaces.  Lines that have spaces will be ignored
		 * @return
		 */
		public LinkedList<String> list_wireless_interface()
		{
			LinkedList <String> list_interfaces = null;
			String [] array = null;
			try
			{						
				if(this.isLinux)
				{
					Process proc = Runtime.getRuntime().exec("iwconfig");
					
					BufferedReader br = new BufferedReader(new InputStreamReader(proc.getInputStream()));
					String line = "";
					
					while((line = br.readLine()) != null)
					{
						//skip lines that begin with a space... i.e. indicating details about a particular interface
						if(line.startsWith(" ") || line.startsWith("\t"))
							continue;
						
						//skip no wireless extension lines
						if(line.toLowerCase().trim().contains("no wireless extensions"))
							continue;
						
						if(line.trim().equals(""))
							continue;
						
						//otw, it must be a valid line, so keep it
						array = line.split(" ");
						
						if(array == null || array.length < 1)
							continue;
						
						if(list_interfaces == null)
							list_interfaces = new LinkedList<String>();
						
						//add name
						list_interfaces.add(array[0].trim());
					}
				}
			}
			catch(Exception e)
			{
				this.eop(myClassName, "list_wireless_interface", e);
			}
			
			return list_interfaces;
		}
		
		public void sop(String out)	{try	{	if(output_enabled)	System.out.println(out);	} catch(Exception e){}}
		
		public static final String status_400_Bad_Request = "400 Bad Request";
		public static final String status_403_Bad_Request = "403 Forbidden";
		public static final String status_404_Not_Found = "404 Not Found";
		
		public static final String disclaimer_ip2location = "This product includes IP2Location LITE data available from http://www.ip2location.com.";
		public static final String authoritative_not_found = "authoritative_not_found";
		public static final String authoritative_found = "authoritative_found";
		
		public void sp(String out)	{try	{	if(output_enabled)	System.out.print(out);	} catch(Exception e){}}
		
		/**stores log file of requester, request, and result*/
		//public static Log log = new Log("log", 100, 100000000);
		
		public volatile static int ap_count = 0, sta_count = 0; 

		public void directive(String out)	{try	{	System.out.println(out);	} catch(Exception e){}}
		public void directivesp(String out)	{try	{	System.out.print(out);		} catch(Exception e){}}
		
		public boolean display_status()
		{
			try
			{
				directive("\n/// STATUS ///");
				directive(FULL_NAME);
				
				directive("");
				directive("Time of First Start: " + TIME_OF_FIRST_START);
				
				directive("");
				try
				{
					directive("");
			
					
				}catch(Exception e){}
				
				directive("");
				//log.display_status();
				
				directive("");
				
				//display server sockets
				directive("");
					
				directive("");
				
				
				directive("");			
				directive("Heap Size: " + Runtime.getRuntime().totalMemory()/1e6 + "(MB) Max Heap Size: " + Runtime.getRuntime().maxMemory()/1e6 + "(MB) Free Heap Size: " + Runtime.getRuntime().freeMemory()/1e6 + "(MB) Consumed Heap Size: " + (Runtime.getRuntime().totalMemory() - Runtime.getRuntime().freeMemory())/1e6 + "(MB)");
				directive("");		
				
				System.gc();
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "display_status", e);
				
			}
			
			return false;
		}
		
		
		
		/**
		 * e.g. (directory_path, true, new String[]{"export, backup, log, wigle, web"},  new LinkedList<File>())
		 * @param topFolder
		 * @param recurse_directories
		 * @param filter
		 * @return
		 */
		public LinkedList<File> getFileListing(File directory, boolean recurse_directories, String [] filter, LinkedList<File> final_list)
		{
			try
			{
				//base case
				if(directory == null)
					return final_list;
				
				if(directory.isDirectory())
				{
					//procure listing
					File [] listing = directory.listFiles();
					
					if(listing == null || listing.length < 1)
						return final_list;
					
					//otw, analyze each file
					for(File fle : listing)
					{
						try
						{												
							//
							//RECURSE!
							//
							if(fle.isDirectory() && recurse_directories)
								getFileListing(fle, recurse_directories, filter, final_list);
							
							if(fle.isFile())
							{
								//
								//check filters
								//
								
								//no filters, add all
								if(filter == null || filter.length < 1)
								{
									if(final_list == null)
										final_list = new LinkedList<File>();
																									
									final_list.add(fle);
									continue;
								}
								
								//specific filters
								for(String fltr : filter)
								{
									try
									{
										if(fltr == null || fltr.trim().equals(""))
											continue;//get next filter
										
										if(fle.toString().toLowerCase().trim().contains(fltr.toLowerCase().trim()))
										{
											if(final_list == null)
												final_list = new LinkedList<File>();
											
											final_list.add(fle);
											continue;
										}
									}
									catch(Exception e)
									{
										continue;
									}
								}
							}
						}
						catch(Exception e)
						{
							continue;
						}
					}
				}
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "getFileListing", e);			
			}
			
			
			
			return final_list;
		}
		
		public String getStackTrace(Exception e)
		{
			try
			{
				StringWriter sw = new StringWriter();
				PrintWriter pw = new PrintWriter(sw);
				e.printStackTrace(pw);
				
				String string = (sw.toString());
				
				try		{	pw.close();	}	catch(Exception ee){}
				try		{	sw.close();	}	catch(Exception ee){}
				
				return string;

			}
			catch(Exception ee)
			{
				this.eop(myClassName, "getStackTrace", ee);
			}
			
			return "";
		}
		
		public static void setLookAndFeel()
		{
			try 
			{	
			    UIManager.setLookAndFeel("com.sun.java.swing.plaf.windows.WindowsLookAndFeel");	
			} 
			catch (Exception e) 
			{
			   // handle exception
			}
		}
		
		public void eop(String myClassName, String mtdName, Exception e)
		{
			try
			{
				directive("[" + e.getClass().getSimpleName() + "] Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
			}
			catch(Exception ee)
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
			}
		}
		
		public boolean is_private_ipv4_address(Socket skt)
		{
			try
			{			
				String ip = skt.getInetAddress().toString();
				
				return is_private_ipv4_address(ip);
			}
			catch(Exception e)
			{
				this.eop(myClassName, "is_private_ipv4_address - skt", e);
			}
			
			return false;
		}
		
		public boolean is_private_ipv4_address(String ip)
		{
			try
			{
				
				
				//
				//determine if private ip first...
				//
				
	/*			RFC1918 name	IP address range	number of addresses	largest CIDR block (subnet mask)	host id size	mask bits	classful description[Note 1]
				24-bit block	10.0.0.0 - 10.255.255.255	16,777,216	10.0.0.0/8 (255.0.0.0)	24 bits	8 bits	single class A network
				20-bit block	172.16.0.0 - 172.31.255.255	1,048,576	172.16.0.0/12 (255.240.0.0)	20 bits	12 bits	16 contiguous class B networks
				16-bit block	192.168.0.0 - 192.168.255.255	65,536	192.168.0.0/16 (255.255.0.0)	16 bits	16 bits	256 contiguous class C networks*/
				
				if(ip == null || ip.trim().equals(""))
					return false;
				
				if(ip.contains("0:0:0:0:0:0:0:"))
					return true;
				
				if(ip.startsWith("/"))
					ip = ip.replaceFirst("/", "");
				
				
				ip = ip.trim();
				
				if(ip.equals("127.0.0.1"))
					return true;
				
				if(ip.startsWith("10"))
					return true;
				
				if(ip.startsWith("192.168"))
					return true;
				
				//don't even begin if doesn't start with
				if(ip.startsWith("10") || ip.startsWith("172") || ip.startsWith("192.168"))
				{
					String array[] = ip.split("\\.");
					
					if(array != null && array.length == 4)
					{
						int octet_0 = Integer.parseInt(array[0].trim());
						int octet_1 = Integer.parseInt(array[1].trim());
						int octet_2 = Integer.parseInt(array[2].trim());
						int octet_3 = Integer.parseInt(array[3].trim());
														
						try
						{
							if(octet_0 == 10)
								return true;
							
							if(octet_0 == 172)
							{
								if(octet_1 >= 16 && octet_1 <= 31)
									return true;
							}
							
							if(octet_0 == 192 && octet_1 == 168)
								return true;
							
						}
						catch(Exception ee)
						{
							//just fall through and resolve the ip
						}		
				}
				
						
					
				}
			}
			catch(Exception e)
			{
				this.eop(myClassName, "is_private_ipv4_address", e);
			}
			
			return false;
		}
		
		public void eop(String myClassName, String mtdName, Exception e, boolean display_stack_trace)
		{
			try
			{
				directive("[" + e.getClass().getSimpleName() + "] Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
				
				if(display_stack_trace)
					e.printStackTrace(System.out);
			}
			catch(Exception ee)
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   "  " + e.getLocalizedMessage());
			}
		}
		
		public void eop_loop(String myClassName, String mtdName, Exception e, int i)
		{
			try
			{
				directive("[" + e.getClass().getSimpleName() + "] Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   " on index [" + i + "]. Message-->"+ e.getLocalizedMessage());
			}
			catch(Exception ee)
			{
				directive("Exception caught in " + myClassName + " class " + "in mtd: " + mtdName +   " on index [" + i + "]. Message-->"+ e.getLocalizedMessage());
			}
		}
		
		
		
		public String get_time_stamp()
		{
			try
			{
				return (new SimpleDateFormat("yyyy-MM-dd-HH:mm.ss").format(new Date()));
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_time_stamp", e);
			}
			
			return "" + System.currentTimeMillis();
		}
		
		public String get_time_stamp(long time)
		{
			try
			{
				return (new SimpleDateFormat("yyyy-MM-dd-HH:mm.ss").format(new Date(time)));
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_time_stamp", e);
			}
			
			return "" + System.currentTimeMillis();
		}
		
		public long ip_to_long(String address)
		{
			try
			{
				//given [73.153.209.154]
				//73 x (256)^3 + 153 x (256)^2 + 209 x (256)^1 + 154 (256)^0 = ?
				//1224736768 + 10027008 + 53504 + 154 = 1234817434
				
				arr_ip = address.split("\\.");
				
				//power through, any error, would catch the exception and move on
				value = 	(Long.parseLong(arr_ip[0].trim()) * pow_256_3) 
						+ 	(Long.parseLong(arr_ip[1].trim()) * pow_256_2)
						+ 	(Long.parseLong(arr_ip[2].trim()) * 256)
						+ 	(Long.parseLong(arr_ip[3].trim()));
					
				//sop("IP Again: " + long_to_ip(value));
				
				return value;			
			}
			catch(Exception e)
			{
				//this.eop(myClassName, "ip_to_long", e);			
			}
			
			return -1;
		}
		
		public String long_to_ip(long address)
		{
			try
			{
				return ((address >> 24) & 0xFF) + "." + ((address >> 16) & 0xFF) + "." + ((address >> 8) & 0xFF) + "."	+ (address & 0xFF);
			}
			catch(Exception e)
			{
				
			}
			
			return "null";
		}
		
		public String get_time_stamp(String delimiter)
		{
			try
			{
				return (new SimpleDateFormat("yyyy" + delimiter + "MM" + delimiter + "dd" + delimiter + "HH" + delimiter + "mm" + delimiter + "ss").format(new Date()));
				
			}
			catch(Exception e)
			{
				this.eop(myClassName, "get_time_stamp", e);
			}
			
			return "" + System.currentTimeMillis();
		}
		
		/**
		 * log all actions
		 * @param line
		 * @return
		 */
		public boolean log(String line)
		{
			try
			{
				//this.log.log(get_time_stamp("-") + ", " +  line);
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "log", e);
			}
			
			return false;
		}
		
		
		
		public  void jop(String strMsg)
		{
			JOptionPane.showMessageDialog(null, strMsg, "Unable to complete selected action...", JOptionPane.INFORMATION_MESSAGE);
		}
		public  void jop_Message(String strMsg)
		{
			JOptionPane.showMessageDialog(null, strMsg, "Message", JOptionPane.INFORMATION_MESSAGE);
		}
		
		public  String jop_Query(String strMsg, String strTitle)
		{
			Object o = strMsg;
			
			return JOptionPane.showInputDialog(null, o, strTitle, JOptionPane.QUESTION_MESSAGE);
		}
			
		public  Object jop_queryJComboBox(String strMessage, String title, String[] arrElements)
		{
			return JOptionPane.showInputDialog(null, strMessage, title, JOptionPane.QUESTION_MESSAGE, null, arrElements, arrElements[0]);
			
		}
		
		public int jop_Query_Custom_Buttons(String msg, String title, Object [] buttons)
		{
			return jop_custom_buttons(msg, title, buttons);
		}
		
		public int jop_custom_buttons(String msg, String title, Object [] buttons)
		{
			
			return JOptionPane.showOptionDialog(null, msg, title, JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE,	null, buttons, buttons[0]);
		}
		
		
		public  int jop_Confirm(String strText, String strTitle)
		{
			try
			{
				//try{Main.playSound(sound_Note);}catch(Exception e){}
				
				return JOptionPane.showConfirmDialog(null, strText, strTitle, JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
			}
			catch(Exception e)
			{
				//Drivers.eop("queryDialog", strMyClassName, e, e.getMessage(), true);
			}
			
			return -1;
		}
		
		public  int jop_Confirm_YES_NO_CANCEL(String strText, String strTitle)
		{
			try
			{
				return JOptionPane.showConfirmDialog(null, strText, strTitle, JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE);
			}
			catch(Exception e)
			{
				//Drivers.eop("queryDialog", strMyClassName, e, e.getMessage(), true);
			}
			
			return -1;
		}	
		
		public  String jop_Password(String strMsg)
		{
			JPasswordField passwordField = new JPasswordField();

			if(JOptionPane.showConfirmDialog(null, passwordField, strMsg, JOptionPane.OK_CANCEL_OPTION, JOptionPane.QUESTION_MESSAGE) == JOptionPane.YES_OPTION)
			{
				//Drivers.sop("Entered PIN: " + new String(passwordField.getPassword()));
				return new String(passwordField.getPassword());
			}
			
			//otw
			return null;

		}
		
		public  boolean jop_Error(String strMsg, String strTitle)
		{
			JOptionPane.showMessageDialog(null, strMsg, strTitle, JOptionPane.ERROR_MESSAGE);
			
			//since we're displaying an error, we'll assume the default return type is false;
			return false;
		}
		
		
		/**
		 * Remove potential ":" or "-" from MAC address
		 * @param MAC
		 * @return
		 */
		public String strip_MAC(String MAC)
		{
			try
			{
				if(MAC == null || MAC.equals(""))
					return MAC;
				
				MAC = MAC.replaceAll("\\-", "");
				MAC = MAC.replaceAll("\\:", "");
						
				return MAC;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "strip_MAC", e);
			}
							
			return MAC;
		}
		
		public boolean copyToClipboard(String text)
		{
			try
			{
				StringSelection strSelection = null;
				Clipboard inject_clipboard = null;
				 
				
				strSelection = new StringSelection(text);
				inject_clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
				inject_clipboard.setContents(strSelection, null);
				
				return true;
			}
			catch(Exception e)
			{
				this.eop(myClassName, "copyToClipboard", e);
			}
			
			return false;
		}
		
		public  boolean jop_Error(String strMsg, boolean playErrorSound)
		{
			try
			{
				if(playErrorSound)
				{
					//try{	Main.playSound(Drivers.sound_Error);	}	catch(Exception ee){}
				}
				
				JOptionPane.showMessageDialog(null, strMsg, "* * Unable to Complete Selected Action... * *", JOptionPane.ERROR_MESSAGE);
			}catch(Exception e){}
			
			//since we're displaying an error, we'll assume the default return type is false;
			return false;
		}
		
		public  void jop_Warning(String strMsg, String strTitle)
		{
			JOptionPane.showMessageDialog(null, strMsg, strTitle, JOptionPane.WARNING_MESSAGE);
		}
		
		public  void jop_Message(String strMsg, String strTitle)
		{
			JOptionPane.showMessageDialog(null, strMsg, strTitle, JOptionPane.INFORMATION_MESSAGE);
		}
		
		public static String getTime_Specified_Hyphenated_with_seconds()
		{
			try
			{
				return getTime_Specified_Hyphenated_with_seconds(-1);
			}
			catch(Exception e)
			{
				System.out.println("check getTime_Specified_Hyphenated_with_seconds in Driver - no params");
			}
			
			return "" + System.currentTimeMillis();
		}
		
		/**Pass -1 to set to default, current time*/
		public static String getTime_Specified_Hyphenated_with_seconds(long time_millis)
		{
			try
			{			
				if(time_millis < 1000)
					time_millis = System.currentTimeMillis();
				
				dateTime_yyyy_mm_dd_hh_mm_ss.setTime(time_millis);			
				return dateFormat_yyyy_mm_dd_hh_mm_ss.format(dateTime_yyyy_mm_dd_hh_mm_ss);
			}
			catch(Exception e)
			{
				System.out.println("Invalid date specified -=##=-" + " it does not a proper date was selected");
				//Drivers.eop("Drivers", "getTime_Specified_Millis", "", e, false);
			}
			
			return "";
		}
		
		
		public String getStringFromList(LinkedList<String> list, String delimiter, long max_count_to_return)
		{
			try
			{
				if(list == null || list.isEmpty())
					return " ";
				
				string_list_search = list.getFirst();
				
				for(int i = 1; i < list.size(); i++)
				{
					string_list_search = string_list_search + delimiter + list.get(i);
					
					if(max_count_to_return > 0 && i > max_count_to_return)
						break;
				}
			}
			catch(Exception e)
			{
				eop(myClassName, "getSSID_List", e);
			}
			
			return string_list_search;
		}
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
	}
	