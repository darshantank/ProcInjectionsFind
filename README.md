# ProcInjectionsFind

A ProcInjectionsFind volatility plugin runs against malware-infected memory images or memory of live VMs and examines each memory region of all running processes to conclude if it is the result of process injection. 

The ProcInjectionsFind volatility module is designed to automate the identification of different process injection strategies.

Although there are numerous process injection techniques, this work focuses on the detection of following eight different implementations of process injection:  

    1. Remote DLL Injection Via CreateRemoteThread and LoadLibrary
    
    2. Remote Thread Injection Using CreateRemoteThread
    
    3. Portable Executable Injection
    
    4. Reflective DLL Injection
    
    5. Hollow Process Injection
    
    6. Thread Execution Hijacking 
    
    7. APC Injection 
    
    8. AtomBombing

This module runs a few checks to pinpoint malicious/injected memory sections and prints various attributes of each injected memory area that match our rules characterized in the algorithms.

One can perform live introspection of running VMs for possible indication of process injection.

The proposed system completely detects more malware families and stands over other systems in all evaluation metrics defined in this work.

We are leveraging virtual machine introspection with memory forensics to detect process injection of varied types in a virtualized environment.

On any questions (regarding this research ;-) ) don't hesitate to contact dmtank@gmail.com
