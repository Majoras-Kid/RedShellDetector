#!/usr/bin/env python

import sys
import argparse
import string
import os
import subprocess

#sudo pip install git+https://github.com/toastdriven/pyskip.git
import pyskip as skiplist


TARGET_DIRECTORY = ""
REDSHELL_LIST = []
REDSHELL_FUNCTIONS = skiplist.Skiplist()
FUNCTION_COUNTER_PER_FILE = dict()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Python script to detect the presence of the RedShell malware")
    parser.add_argument('directory',metavar='dir',type=str,help="Directory that will be checked,")
    args = parser.parse_args()
    return args

def identify_dll_functions(dll_name):
    function_names = ""
    print("Executing: objdump -p %s" % dll_name)
    #execute object-dump: objdump -p example.dll
    function_names_raw = subprocess.getoutput("objdump -p %s" %dll_name)
    
    for line in function_names_raw.splitlines():
        func_name = (line.split(" "))[-1]
        #print(func_name)
        function_names+=func_name + "\n" 

   # print("Extracted functions: %s" % function_names)
    return (function_names)

    #for line in function_names.splitlines():
    #    print((line.split(" "))[-1])

def extract_redshell_functions_from_reference_file():
    global REDSHELL_FUNCTIONS
    print("Extracting all reference RedShell files")
    REDSHELL_PATH = "redshell_reference/"
    
    for name in os.listdir(REDSHELL_PATH):
        print("Filename: %s" %name)
        
        function_names = (identify_dll_functions("%s%s" % (REDSHELL_PATH,name)))    
        
        for func_name in function_names.split("\n"):
            if func_name not in REDSHELL_FUNCTIONS and func_name != "":
                #print("Adding Func:%s to REDSHell" % func_name)
                REDSHELL_FUNCTIONS.insert(func_name)
            

    #print("Redshell_functions skiplist:")

    print("REDSHELL_FUNCTIONS created")

def check_target_dll_with_redshell_reference(target_dll_functions):
    counter = 0
    for func in target_dll_functions.split("\n"):
        if func in REDSHELL_FUNCTIONS:
            #rint("Func %s is in RedShell reference function" % func)
            counter +=1
    return counter
def print_statistic():
    print("\n#### Printing generated statistic")
    print("Print number of functions of RedShell reference found in each file")
    print("File\t\t\t\t\t\t\tCount\n")
    for x in FUNCTION_COUNTER_PER_FILE:
        print("%s\t\t\t\t\t%s" % (x,FUNCTION_COUNTER_PER_FILE[x]))


def crawl_directory():
    global TARGET_DIRECTORY
    global FUNCTION_COUNTER_PER_FILE
    args = parse_arguments() 
    TARGET_DIRECTORY = args.directory
    print("Checking directory: %s" % TARGET_DIRECTORY)

    for dirName, subdirList, fileList in os.walk(TARGET_DIRECTORY):
        #print('Found directory: %s' % dirName)
        if "reshell" in dirName:
            print("Found Path: %s" % dirName)
        for fname in fileList:
            
            #testing for Redshell in filename
            if "redshell" in fname.lower():
                print('Found File: %s/%s' % (dirName,fname))
                
            if ".dll" not in fname:
                continue
            else:
                print("Testing %s" % fname)
            #testing for function names
            print("Testing file %s/%s for function presence"% (dirName,fname))
            function_names = identify_dll_functions("%s%s" % (dirName,fname))
            counter = check_target_dll_with_redshell_reference(function_names)

            if ("%s%s" % (dirName,fname)) not in FUNCTION_COUNTER_PER_FILE:
                FUNCTION_COUNTER_PER_FILE["%s%s" % (dirName,fname)] = counter
            else:
                print("Key %s%s already in map" % (dirName,fname))
            
            

    print_statistic()
#crawl_directory()

extract_redshell_functions_from_reference_file()
crawl_directory()
#identify_dll_functions("examples/example.dll")