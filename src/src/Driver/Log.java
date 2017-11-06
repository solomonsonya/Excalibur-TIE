package Driver;

/**
 * @author Solomon Sonya
 * */


import javax.swing.*;
import javax.swing.Timer;
import java.io.*;
import java.util.*;
import java.awt.event.*;


public class Log extends Thread implements Runnable, ActionListener
{
	public static final String myClassName = "Log";
	
	public static volatile Driver driver = new Driver();
	
	private volatile LinkedList<String> queue = new LinkedList<String>();
	
	public volatile boolean logging_enabled = true;
	
	Timer tmr = null;
	public int millis_interrupt = 100;
	
	public volatile boolean handle_interrupt = true;
	
	public volatile File fleLogDirectory = null;
	public volatile File fleLogFile = null;
	public volatile PrintWriter pwOut = null;
	
	public volatile String TOP_FOLDER_NAME = "";
	public volatile String TOP_FOLDER_PATH = "";
	public volatile String LOG_FILE_NAME = "";
	public volatile int MAX_LOG_SIZE_BYTES = -1;
	
	public Log(String log_name, int interrupt_time, int max_log_size_bytes)
	{
		try
		{
			LOG_FILE_NAME = log_name;
			
			if(LOG_FILE_NAME == null || LOG_FILE_NAME.trim().equals(""))
				LOG_FILE_NAME = "log";
			
			millis_interrupt =  interrupt_time;
			
			if(millis_interrupt < 1)
				millis_interrupt = 1;
			
			MAX_LOG_SIZE_BYTES = max_log_size_bytes;
			
			ensure_logging_configuration(false);
			
			this.start();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 1", e);
		}
	}
	
	public Log(String top_folder_name, String log_name, int interrupt_time, int max_log_size_bytes)
	{
		try
		{
			LOG_FILE_NAME = log_name;
			
			TOP_FOLDER_NAME = top_folder_name;
			
			if(LOG_FILE_NAME == null || LOG_FILE_NAME.trim().equals(""))
				LOG_FILE_NAME = "log";
			
			millis_interrupt =  interrupt_time;
			
			if(millis_interrupt < 1)
				millis_interrupt = 1;
			
			MAX_LOG_SIZE_BYTES = max_log_size_bytes;
			
			ensure_logging_configuration(false);
			
			this.start();
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "Constructor - 2", e);
		}
	}
	
	public void run()
	{
		try
		{
			tmr = new Timer(millis_interrupt, this);
			tmr.start();
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "run", e);
		}
	}
	
	public boolean display_status()
	{
		try
		{
			ensure_logging_configuration(false);
			driver.directive("[" + LOG_FILE_NAME.toUpperCase() + "] to location --> " + fleLogFile.getCanonicalPath());
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "display_status", e);
		}
		
		return false;
	}
	
	public boolean log(String line)
	{
		try
		{
			if(this.logging_enabled)
				this.queue.addLast(line);
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "log", e);
		}
		
		return false;
	}
	
	public void actionPerformed(ActionEvent ae)
	{
		try
		{
			if(ae.getSource() == tmr && !queue.isEmpty())
			{
				process_interrupt();
			}
			
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ae", e);
		}
		
	}
	
	public boolean ensure_logging_configuration(boolean verbose)
	{
		try
		{
			//
			//ensure log directory exists
			//
			if(fleLogDirectory == null || !fleLogDirectory.exists() || !fleLogDirectory.isDirectory())
			{
				fleLogDirectory = new File("./");
				
				if(fleLogDirectory.getCanonicalPath().endsWith(File.separator))
				{
					//check if there's an additional folder path
					if(TOP_FOLDER_NAME != null && !TOP_FOLDER_NAME.trim().equals(""))
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + Driver.NAME + File.separator + "log" + File.separator + TOP_FOLDER_NAME.trim());
					else
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + Driver.NAME + File.separator + "log");					
				}
				else
				{
					if(TOP_FOLDER_NAME != null && !TOP_FOLDER_NAME.trim().equals(""))
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + File.separator + Driver.NAME + File.separator + "log" + File.separator + TOP_FOLDER_NAME.trim());
					else
						fleLogDirectory = new File(fleLogDirectory.getCanonicalPath() + File.separator + Driver.NAME + File.separator + "log");
				}
				
				
				
				
				try	{	fleLogDirectory.mkdirs();	}	catch(Exception e){}
				
				TOP_FOLDER_PATH = fleLogDirectory.getCanonicalPath();
				
				if(verbose)
					driver.sop("Log file directory set to " + fleLogDirectory.getCanonicalPath());
			}
			
			//
			//ensure log file exists
			//
			if(this.fleLogFile == null || !fleLogFile.exists() || !fleLogFile.isFile())
			{
				if(fleLogDirectory.getCanonicalPath().endsWith(File.separator))
				{
					fleLogFile = new File(fleLogDirectory.getCanonicalPath() + this.LOG_FILE_NAME + "_" + driver.get_time_stamp("_") + ".txt");	
					pwOut = new PrintWriter(new FileWriter(fleLogFile));
					
					if(verbose)
						driver.sop("Log file created at " + fleLogFile.getCanonicalPath());
				}
				else
				{
					fleLogFile = new File(fleLogDirectory.getCanonicalPath() + File.separator + this.LOG_FILE_NAME + "_" + driver.get_time_stamp("_") + ".txt");	
					pwOut = new PrintWriter(new FileWriter(fleLogFile));
					
					if(verbose)
						driver.sop("Log file created at " + fleLogFile.getCanonicalPath());
				}
			}
			
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "ensure_logging_configuration", e);
		}
		
		return false;
	}
	
	public boolean process_interrupt()
	{
		try
		{
			if(!logging_enabled)
				return false;
			
			if(!handle_interrupt)
				return true;
			
			if(this.queue.isEmpty())
				return true;
			
			handle_interrupt = false;
			
			ensure_logging_configuration(true);
			
						
			//
			//Write contents
			//
			//pwOut.println(this.queue.removeFirst());
			//pwOut.flush();
			
			//
			//check if there are any remaining contents in the queue, if so, exhaust queue here...
			//
			while(!queue.isEmpty())
			{
				pwOut.println(this.queue.removeFirst());
				pwOut.flush();
			}
			
			//
			//Check if max size reached
			//
			if(this.MAX_LOG_SIZE_BYTES > 0 && this.fleLogFile != null && this.fleLogFile.length() > this.MAX_LOG_SIZE_BYTES)
			{
				try	{	pwOut.close();	}	catch(Exception e){};
				
				//set to null so we know to allocate a new file
				fleLogFile = null;
			}
			
			handle_interrupt = true;
			return true;
		}
		catch(NoSuchElementException nse)
		{
			handle_interrupt = true;
			try	{	pwOut.flush();	}	catch(Exception ee){}
			return true;
		}
		catch(Exception e)
		{
			driver.eop(myClassName, "process_interrupt", e);
		}
		
		handle_interrupt = true;
		
		return false;
	}

}
