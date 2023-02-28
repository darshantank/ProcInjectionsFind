# -*- coding: utf-8 -*-

# Author: Darshan M Tank
# Email : dmtank@gmail.com
# Twitter: @darshan_m_tank

# Plugin Name: ProcInjectionsFind

# Description: A volatility plugin to detect following types of process injections. 
	# 1. Classic DLL Injection Via CreateRemoteThread and LoadLibrary
	# 2. Simple Thread Injection Using CreateRemoteThread
	# 3. Portable Executable Injection 
	# 4. Reflective DLL Injection
	# 5. Hollow Process Injection
	# 6. Thread Execution Hijacking
	# 7. APC Injection
	# 8. AtomBombing

# GetInjectedThread is a Volatility plugin to detect varied types of process injections. It displays attributes for each injected memory region (VAD).

# This plugin should allow a security analyst to get the process related information and spot any process anamoly without having to run multiple plugins.

'''
### Running the Plugin

Copy the plugin to volatility/plugins directory

Run the plugin against malware-infected windows memory image as shown below

$ python vol.py -f win7-Guest-clone.mem --profile=Win7SP1x64 procinjectionsfind
$ python vol.py -f win10-Guest-clone.mem --profile=Win10x64_14393 procinjectionsfind

Run the plugin against memory of a live VM as shown below

$ python vol.py -l vmi://win7_Guest --profile=Win7SP1x64 procinjectionsfind
$ python vol.py -l vmi://win10_Guest --profile=Win10x64_14393 procinjectionsfind
'''

# python vol.py --plugins=/home/dmt/volatility/procinjectionsfind/ -f /home/dmt/memory-dump-files/win7-Guest-clone-36.mem --profile=Win7SP1x64 procinjectionsfind -p 1744

# python vol.py --plugins=/home/dmt/volatility/procinjectionsfind/ -f /home/dmt/memory-dump-files/win10-pe-injection.mem --profile=Win10x64_14393 procinjectionsfind -p 5468

# python vol.py --plugins=/home/dmt/volatility/procinjectionsfind/ -l vmi://win10_Guest --profile=Win10x64_14393 procinjectionsfind -p 5468

import os
import ntpath
import time
import distorm3
import volatility.conf as conf
import volatility.utils as utils
import volatility.win32 as win32
import volatility.plugins.common as common
import volatility.plugins.vadinfo as vadinfo
import volatility.plugins.malware.malfind as malfind

from volatility.plugins.modules import Modules
from volatility.plugins.taskmods import PSList

# 'VadImageMap'
IMAGE_FILE_TYPE = 2
start_time = time.time()

# if vad.Start <= thread.Win32StartAddress <= vad.End and vad.u.VadFlags.VadType.v() != IMAGE_FILE_TYPE and vad.u.VadFlags.MemCommit.v() == 1:

class ProcInjectionsFind(vadinfo.VADDump):
	"""Print attributes for each injected memory region (VAD)"""

	def __init__(self, config, *args, **kwargs):
        	vadinfo.VADDump.__init__(self, config, *args, **kwargs)
		self.get_proc_vads = []
		self.pid_ppid_list = []

	def get_threads_for_process(self, task):

        	for thread in task.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
            		yield thread

	def get_vad_for_process(self, task):

        	proc_vad_range = []

        	for vad, addr_space in task.get_vads():
            		proc_vad_range.append((vad, addr_space))

        	return proc_vad_range

	def check_where_in_vad(self, thread_entry_point):

        	for vad, addr_space in self.get_proc_vads:
            		# Check if the thread's function is within the vad range 
            		if vad.Start <= thread_entry_point <= vad.End:
                		return (vad, addr_space)

        	return ()
	
	def get_vad_file_object(self, vad_object):

        	try:
            		file_name = vad_object.FileObject.FileName.v()
        	except AttributeError:
            		return ''
       		else:
            		return file_name

	def parse_process(self, proc_object):

		# --- 100 line ---
		process = proc_object
		process_name = process.ImageFileName
		process_pid = process.UniqueProcessId
		process_ppid = process.InheritedFromUniqueProcessId
		process_active_threads = process.ActiveThreads

		output =    "Process: {0}"\
                            "\tPID: {1}"\
                            "\tPPID: {2}"\
                            "\tActive Threads: {3}\n".format(process_name,
                                                      process_pid,
                                                      process_ppid,
                                                      process_active_threads)

		return output

	# --- 100 lines ---
	def parse_thread(self, thread_object):
	
		thread = thread_object
		thread_id = thread.Cid.UniqueThread.v()
		thread_entry_point = thread.Win32StartAddress
		thread_BasePriority = thread.Tcb.BasePriority
		thread_Priority = thread.Tcb.Priority
		thread_Teb = thread.Tcb.Teb
		thread_CrossThreadFlags = thread.CrossThreadFlags

		# Check if the thread is terminated
		if thread.Terminated != 0:
        		thread_state = 'Terminated'
        	else:
                	thread_state = 'Active'
	
		output =    "\tThread ID: {0}\n"\
                    	    "\tThread State: {1}\n"\
                    	    "\tThread Entry Point: {2:#x}\n"\
                    	    "\tThread BasePriority: {3}\n"\
                    	    "\tThread Priority: {4}\n"\
		    	    "\tThread TEB: {5:#x}\n"\
                    	    "\tThread CrossThreadFlags: {6}\n\n".format(thread_id,
                                                 		 thread_state,
                                                 		 thread_entry_point,
                                                 		 thread_BasePriority,
                                                 		 thread_Priority,
						 		 thread_Teb,
						 		 thread_CrossThreadFlags)

		return output 

	def parse_vad(self, vad_object):

        	vad = vad_object
        	vad_start = vad.Start
        	vad_end = vad.End
        	vad_size = vad_end - vad_start
		vad_tag = vad.Tag
        	vad_protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v())
		vad_flags = str(vad.VadFlags)
		vad_type = vadinfo.MI_VAD_TYPE.get(vad.VadFlags.VadType.v())
        	file_name = self.get_vad_file_object(vad_object)
        	file_name = file_name if file_name else "''"

        	output =    "\tVAD Base Address: {0:#x}\n"\
                    	    "\tVAD End Address: {1:#x}\n"\
                    	    "\tVAD Size: {2:#x}\n"\
                    	    "\tVAD Tag: {3}\n"\
                    	    "\tVAD Protection: {4}\n"\
		    	    "\tVAD Flags: {5}\n"\
			    "\tVAD Type: {6}\n"\
                    	    "\tVAD Mapped File: {7}\n\n".format(vad_start,
                                                 	 vad_end,
                                                 	 vad_size,
                                                 	 vad_tag,
                                                 	 vad_protection,
						 	 vad_flags,
							 vad_type,
						 	 file_name)

        	return output

	def disassemble_vad(self, process_address_space_object, vad_object):
		
		address_space = process_address_space_object
		vad = vad_object
		content = address_space.read(vad.Start, 64)
		
		if content:

			disassemble_code = "\t"
	        	disassemble_code += ("{0}\n\n".format("\n\t".join(
			["{0:#010x}  {1:<48}  {2}".format(vad.Start + o, h, ''.join(c)) 
			for o, h, c in utils.Hexdump(content)])))

			disassemble_code += "\t"

                	disassemble_code += "\n\t".join(["{0:#010x} {1:<16} {2}".format(o, h, i)  \
					      for o, i, h in \
					      malfind.Disassemble(content, vad.Start)])
		else:
			# --- 200 line ---
        		disassemble_code = "\t** Couldn't read memory\n"

		return disassemble_code

	def disassemble_thread(self, process_address_space_object, thread_object):

		address_space = process_address_space_object
		thread = thread_object
		thread_entry_point = thread.Win32StartAddress
		content = address_space.read(int(thread_entry_point), 64)

		if content:
		
			disassemble_code = "\t"
	        	disassemble_code += ("{0}\n\n".format("\n\t".join(
                	["{0:#010x}  {1:<48}  {2}".format(int(thread_entry_point) + o, h, ''.join(c))
                 	for o, h, c in utils.Hexdump(content)])))

        		disassemble_code += "\t"

			disassemble_code += "\n\t".join(["{0:#010x} {1:<16} {2}".format(o, h, i)  \
					      for o, i, h in \
					      malfind.Disassemble(content, int(thread_entry_point))])

			'''
			mode = address_space.profile.metadata.get('memory_model')
                	if mode == '64bit':
                    		mode = distorm3.Decode64Bits
                	else:
                    		mode = distorm3.Decode32Bits
                	disassemble_code += "\n\t".join(["{0:<#010x} {1:<16} {2}".format(o, h, i) \
                                              for o, _size, i, h in \
                                              distorm3.DecodeGenerator(int(thread_entry_point), content, mode)])
			'''

		else:
        		disassemble_code = "\t** Couldn't read memory\n"

		return disassemble_code
	
	def check_if_thread_is_suspended(self, thread):

		# Lookup the thread's state
            	state = str(thread.Tcb.State)

		# Find the wait reason
            	if state == 'Waiting':
                	wait_reason = str(thread.Tcb.WaitReason)
            	else:
                	wait_reason = ''
		
		# Check if thread is suspended
                if state == 'Waiting' and wait_reason == 'Suspended':
			return True
		else:
			return False

	def is_vad_empty(self, vad, address_space):
        
        	PAGE_SIZE = 0x1000
        	all_zero_page = "\x00" * PAGE_SIZE

        	offset = 0
        	while offset < vad.Length:
            		next_addr = vad.Start + offset
            		if (address_space.is_valid_address(next_addr) and address_space.read(next_addr, PAGE_SIZE) != all_zero_page):
                		return False
            		offset += PAGE_SIZE

        	return True

	def injection_filter_thread(self, vad):
	
		# check-1 --> Find unmapped threads in process memory
		# Unmapped thread: A thread in the process that is mapped to a VAD without a file 					  object.
		if hasattr(vad,"ControlArea") == False:
			#print 1
			return True

		# check-2 --> A thread in the process that is mapped to a VAD with a file object, but 				     the memory is committed and the type of file is not an image file.
		if hasattr(vad.VadFlags,"MemCommit") == True:
			if vad.VadFlags.MemCommit.v() == 1 and vad.VadFlags.VadType.v() != IMAGE_FILE_TYPE:
				#print 2
				return True
		
			return False

	def injection_filter_vad(self, process_space, vad):
		
		protection = vadinfo.PROTECT_FLAGS.get(vad.VadFlags.Protection.v(), "")
		vad_type = vadinfo.MI_VAD_TYPE.get(vad.VadFlags.VadType.v(), "")

		# check-3 --> Found signature ("MZ") with no ControlArea and PAGE_EXECUTE_READWRITE 			permission in VAD
		''' 
		data = process_space.read(vad.Start, 1024)
		if data:
			found = data.find("MZ")
			if found != -1:
				if hasattr(vad,"ControlArea") == False and protection == "PAGE_EXECUTE_READWRITE":
					print 3
					return True
		'''
		# check-4 --> Detects Hollow Process Injection 

		if vad.Tag != "VadS":
			control_area = vad.ControlArea
			if not control_area:
            			return
			if hasattr(vad.VadFlags,"ImageMap") == True:
				if vad.VadFlags.ImageMap != 1 and control_area.u.Flags.Image != 1:
					#print 4
            				return True
		
		# check-5 --> Detects APC Injection & AtomBombing 

		if hasattr(vad.VadFlags,"CommitCharge") == True:
			if vad.VadFlags.PrivateMemory == 1 and vad.Tag == "VadS" and protection == "PAGE_EXECUTE_READWRITE" and vad_type == "VadNone" and vad.VadFlags.CommitCharge == 1 and vad.VadFlags.MemCommit == 1:
				#print 5
            			return True

		return False

	def calculate(self):

		# Get processes
        	ps = PSList(self._config)
        	psdata = ps.calculate()

	        for proc in psdata:

			self.get_proc_vads = self.get_vad_for_process(proc)

			for thread in self.get_threads_for_process(proc):
				
				thread_entry_point = thread.Win32StartAddress
				in_vad_range = self.check_where_in_vad(thread_entry_point)
				
				if in_vad_range:

					vad, vad_addr_space = in_vad_range

					if self.injection_filter_thread(vad) == True:
						# check if VAD is empty
						if self.is_vad_empty(vad, proc.get_process_address_space()):
                    					continue
						yield (proc, vad)

					# check-3 --> Find a thread in the process that is mapped to a VAD that contains an exe file object that is same as loaded process's image file, but a thread is suspended.

					if self.get_vad_file_object(vad).split(".")[-1].lower() == "exe":
						thread_mapped_proc_image_file = ntpath.basename(str(self.get_vad_file_object(vad)))
						#print thread_mapped_proc_image_file
						
						if str(thread_mapped_proc_image_file) == str(proc.ImageFileName):
							#print 99
							if self.check_if_thread_is_suspended(thread) == True:
								print "Found suspended thread"
								yield (proc, vad)
						'''
						else:
							print "Found different exe file object from the loaded process's image file"
							yield (proc, vad)
						'''
						#print ntpath.basename(str(self.get_vad_file_object(vad)))
						#print proc.ImageFileName

		
		#for proc in psdata:
			process_space = proc.get_process_address_space()
			for vad in proc.VadRoot.traverse():
				if self.injection_filter_vad(process_space, vad) == True:
					if self.is_vad_empty(vad, proc.get_process_address_space()):
                    				continue
					yield (proc, vad)

	def render_text(self, outfd, data):
		
        	outfd.write("\n\nProcess Injections Find Information:\n\n")
		verbose = self._config.verbose
        	dump_dir = self._config.DUMP_DIR

        	# Check if -D (dump dir) is passed and directory exists
        	if dump_dir and not os.path.isdir(dump_dir):
            		debug.error("'{}' was not found".format(dump_dir))

		for proc, vad in set(data):
			address_space = proc.get_process_address_space()
			# Print out process information	
			outfd.write("------------------------------------------------------------------------------------" + '\n')
			outfd.write(self.parse_process(proc))
			outfd.write("------------------------------------------------------------------------------------" + '\n')
			'''
			# Print out thread information
			outfd.write("Thread Info:\n")
			outfd.write(self.parse_thread(thread))
			'''
			# Print out thread's mapped VAD information
			outfd.write("VAD Info:\n")
			outfd.write(self.parse_vad(vad))

			# Print out disassembly	at vad's start address
			outfd.write("Disassembly Info:\n")
			outfd.write(self.disassemble_vad(address_space, vad))
			outfd.write("\n")
			'''
			# Dump the vad data
			proc_pid = proc.UniqueProcessId
			thread_id = thread.Cid.UniqueThread.v()
			thread_entry_point = thread.Win32StartAddress

                        if dump_dir:
                            filename = "Process.{0}.Vad.{1:#x}.dmp".format(proc.UniqueProcessId, vad.Start)
                            full_path = os.path.join(dump_dir, filename)
                            self.dump_vad(full_path, vad, address_space)
			'''

			'''
			# Print out Disassembly	of thread's entry point
			outfd.write("Disassembly Info:\n")
			outfd.write(self.disassemble_thread(address_space, thread))
			outfd.write("\n")
			
			# Dump thread's entry point data
			proc_pid = proc.UniqueProcessId
			thread_id = thread.Cid.UniqueThread.v()
			thread_entry_point = thread.Win32StartAddress

                        if dump_dir:
                            filename = "Process.{0}.Thread.{1}.entrypoint.{2:#x}.dmp".format(proc_pid, thread_id, thread_entry_point)
                            full_path = os.path.join(dump_dir, filename)
                            self.dump_vad(full_path, vad, address_space)
			'''
			
		end_time = time.time()
		print "\nElapsed Wall-Clock Time: " + str(end_time - start_time) + " seconds" + "\n"

