import os, sys, json
from pathlib import Path

# python script to perform:
#	1. conversion of C code into ASM (.S);
#	2. analysis of system calls in all converted files.

source_dir = '/home/ubuntu/courses/691/HaSS/Datasets/benign_asm-binary'

# NOTE: original - files will retain system calls; nop - files will have nop instead of call statements
orig_ASM_dir = '/home/ubuntu/courses/691/riscv-malware-analysis/benign_asm-orig'
nop_ASM_dir = '/home/ubuntu/courses/691/riscv-malware-analysis/benign_asm-nop'
binary_ASM_dir = '/home/ubuntu/courses/691/riscv-malware-analysis/benign_asm-binary'

path_to_rars = '/home/ubuntu/courses/691/Documents/rars_0e138d8.jar'

# max_file_count -- specify how many benign C files to consider:
max_file_count = 5000

# dictionary to tally all system calls found in the files:
all_system_calls = {}

# flag to determine if second pass of ASM file correction should be done:
flag_do_2nd_pass = True

def convert_to_ASM_1st_pass(asm_file_name, nop_asm_file_name):
	try:
		asm_file = open(asm_file_name, 'r')
		nop_asm_file = open(nop_asm_file_name, 'w')
	except Exception:
		return

	lines = asm_file.readlines()
	for l in lines:
		# do system call analysis:
		
		# split line into operand and opcode:
		instruction = l.split('\t')
		instruction = [x for x in instruction if x]

		if instruction[0] == "call":
			if len(instruction) >= 2:
				#print(l)
				sys_call = instruction[1].rstrip()

				if sys_call in all_system_calls:
					all_system_calls[sys_call] += 1
				else:
					all_system_calls[sys_call] = 1

				# do nop writing - replace system call with nop:
				nop_asm_file.write('\taddi x0, x0, 0\n')
		else:
			nop_asm_file.write(l)
		#endif
	#endfor

	asm_file.close()
	nop_asm_file.close()
#enddef

def convert_to_ASM_2nd_pass(nop_asm_file_name, all_error_lineno):
	# function to iterate through a file that has already been converted into ASM and replace any problematic lines (given by 1st arg):

	# store all modified lines temporarily into an array and then write them to the file:
	nop_asm_file = open(nop_asm_file_name, 'r'); 	lines = nop_asm_file.readlines()
	nop_asm_file.close()

	# use a counter to help us determine when we have hit the problematic lines:
	count = 0

	# now let's write the modified lines to the file:
	nop_asm_file = open(nop_asm_file_name, 'w')
	
	for l in lines:
		count += 1 

		# check if this line exists in the list of error lines:
		if count in all_error_lineno:
			# replace with nop
			nop_asm_file.write('\taddi x0, x0, 0\n')
		else:
			# keep original line
			nop_asm_file.write(l)
		#end
	#end
		
	nop_asm_file.close()

#enddef
		
def main():

	# make the folders containing the ASM files:
	if not os.path.exists(orig_ASM_dir):
		os.makedirs(orig_ASM_dir)

	if not os.path.exists(nop_ASM_dir):
		os.makedirs(nop_ASM_dir)

	if not os.path.exists(binary_ASM_dir):
		os.makedirs(binary_ASM_dir)


	count = 0
	try:
		for file_path in Path(source_dir).rglob('*.c'):
			count += 1

			# setting names of files:
			asm_file_name = orig_ASM_dir + '/' + str(count) + '-' + str(file_path.name[:file_path.name.index('.c')]) + '.asm'
			nop_asm_file_name = nop_ASM_dir + '/' + str(count) + '-' + str(file_path.name[:file_path.name.index('.c')]) + '.asm'


			# run the GCC command to assemble C files inside of their respective projects:
			os.system('riscv64-unknown-linux-gnu-gcc -march=rv32ima -mabi=ilp32 -O0 -S "' + str(file_path) + '" -o "' + str(asm_file_name) + '"')
			
			# now that we have (potentially) created the ASM file, open it and run through system calls:
			if os.path.exists(asm_file_name):
				# open files:
				convert_to_ASM_1st_pass(asm_file_name, nop_asm_file_name)

				# call RARS on nop file to convert ASM to binary string:
			#endif
			if count > max_file_count:
				break
		#endfor	
	except OSError:
		pass

	# look for ASM files that are already provided by the Linux_VX dataset:
	for file_path in Path(nop_ASM_dir).rglob('*.asm'):
		nop_asm_file_name = str(file_path.absolute())
	
		# call RARS on nop file to convert ASM to binary string:
		binary_text_file = binary_ASM_dir + '/' + str(file_path.name) + '.txt'
		
		# do conversion to binary text file:	
		flag = True
		while flag and flag_do_2nd_pass:
			# store RARS output into a text file:
			os.system('java -jar ' + path_to_rars  + ' a dump .text BinaryText ' + binary_text_file + ' ' + nop_asm_file_name + ' & > rars_log.txt')
				
			# check the log file for any errors that prevented binary string output:
			# - we can treat the error lines as nop for now
			try:
				log_file = open('rars_log.txt', 'r'); 
			except Exception:
				print('something went wrong here - no log file produced!')
			else:
				# store all erroneous line numbers mentioned in the log here:
				all_error_lineno = []
				lines = log_file.readlines()
				# check if there is a line referencing an error:
				for l in lines:
					if 'Error' in l:
						# find the line number based on strings in the text:
						lineno = l[l.index(' line ')+len(' line '):]
						if 'column' in lineno:
							lineno = int(lineno[:lineno.index(' column')])
						else:
							lineno = int(lineno[:lineno.index(':')])							
						all_error_lineno.append(lineno)
					#end
				#end
	
				# check if there were any errors found (i.e. this array is not empty):
				if all_error_lineno:
					convert_to_ASM_2nd_pass(nop_asm_file_name, all_error_lineno)
				else:
					# this means we fixed all RARS errors:
					flag = False
				#end
			#end
		#end

		# delete the temporary file created to store output from RARS:
		#if os.path.exists('rars_log.txt'):
		#	os.remove('rars_log.txt')
	#endfor	
#end

if __name__ == '__main__':
	main()

	# save result of system call analysis:				
	json.dump(all_system_calls, open('system_calls.json', 'w'), indent=1, sort_keys=True)

