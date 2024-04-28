import sys, os, random, tqdm

trial_count = 0
malware_string_mapping = {}

# options for detection:
use_ngrams = True
string_match_method = "partial"
if use_ngrams:
	string_match_method = "whole"

class AIS_NegativeSelection(object):
	# constructor method:
	def __init__(self):
		# NOTE: self_set -- set of benign strings, detector_set -- set of malicious strings
		self.self_set = set()
		self.detector_set = set()

	def buildSelfSet(self, sample):
		# take each string from a benign example and add to self set:
		for string in sample['binary_strings']:
			self.self_set.add(string)

	def buildDetectorSet(self, sample):
		if string_match_method == "whole":
			self.buildDetectorSet_wholeMatch(sample)
		else :
			self.buildDetectorSet_partialMatch(sample)
		return

	def buildDetectorSet_partialMatch(self, sample):
		global malware_string_mapping, benign_asm_data, malicious_asm_data
		for string in sample['binary_strings']:
			# get last 7 bits corresponding to the opcode:
			partial_string = string[-7:]
			if partial_string not in self.self_set:
				self.detector_set.add(partial_string)
				if sample['name'] in malware_string_mapping:
					malware_string_mapping[sample['name']].append(partial_string)
				else:
					malware_string_mapping[sample['name']] = [partial_string]
				#endif				

	def buildDetectorSet_wholeMatch(self, sample):
		# take each string from a malicious example and add to detector set if not in self set:
		global malware_string_mapping, benign_asm_data, malicious_asm_data
		for string in sample['binary_strings']:
			if string not in self.self_set:
				self.detector_set.add(string)
				if sample['name'] in malware_string_mapping:
					malware_string_mapping[sample['name']].append(string)
				else:
					malware_string_mapping[sample['name']] = [string]
				#endif				

	def testForAnomaly(self, sample):
		if string_match_method == "whole":
			return self.testForAnomaly_wholeMatch(sample)
		return self.testForAnomaly_partialMatch(sample)

	def testForAnomaly_wholeMatch(self, sample):
		if len(sample['binary_strings']) == 0:
			return -1		
		count = 0		
		for string in sample['binary_strings']:
			if string in self.detector_set:
				count += 1
		# measure the amount of overlap to detector set:
		#return count > 0
		if count / len(sample['binary_strings']) >= 0.01:
			return 1
		return 0
			
	def testForAnomaly_partialMatch(self, sample):
		if len(sample['binary_strings']) == 0:
			return -1		
		count = 0		
		for string in sample['binary_strings']:
			partial_string = string[-7:]
			if partial_string in self.detector_set:
				count += 1
		# measure the amount of overlap to detector set:
		if count / len(sample['binary_strings']) >= 0.01:
			return 1
		return 0

#enddef
	
def loadData(benign_data_dir, malicious_data_dir):
	# Build dictionary with format:	
	#	{"file_1" : {"binary_strings" : [xxxxxxxx, xxxxxxxx, xxxxxxx ... ], "class" : 1 (benign) / 2 (malicious) }, ... }

	# read and extract benign file data:
	benign_asm_data = {}; benign_asm_file_names = []
	for file in os.listdir(benign_data_dir):
		binary_strings = []

		# open the contents of the binary file:
		binary_asm_file = open(os.path.join(benign_data_dir, file), 'r'); lines = binary_asm_file.readlines()
		for L in lines:
			# read each binary string in the file and remove trailing new-line (\n) using rstrip():
			binary_strings.append(L.rstrip())	

		benign_asm_data[str(file)] = {"name" : str(file), "binary_strings" : binary_strings, "class" : 1}
		benign_asm_file_names.append(str(file))

	# read and extract malicious file data:
	malicious_asm_data = {}; malicious_asm_file_names = []
	for file in os.listdir(malicious_data_dir):
		binary_strings = []

		# open the contents of the binary file:
		binary_asm_file = open(os.path.join(malicious_data_dir,file), 'r'); lines = binary_asm_file.readlines()
		for L in lines:
			# read each binary string in the file and remove trailing new-line (\n) using rstrip():
			binary_strings.append(L.rstrip())	

		malicious_asm_data[str(file)] = {"name" : str(file), "binary_strings" : binary_strings, "class" : 2}
		malicious_asm_file_names.append(str(file))
	return benign_asm_data, benign_asm_file_names, malicious_asm_data, malicious_asm_file_names

def createNgram(benign_asm_data, malicious_asm_data,  ngram_size):
	benign_ngram_model, malicious_ngram_model = {}, {}

	# create x-gram (x goes from 2 to 8) for benign data examples:
	benign_ngram_model = {}
	for entry in benign_asm_data:
		# create n-grams of opcodes:
		ngrams = []
		for y in range(len(benign_asm_data[entry]['binary_strings']) - ngram_size + 1):
			subset = benign_asm_data[entry]['binary_strings'][y:y+ngram_size]
			ngram_string = str()
			for s in subset:
				ngram_string += s[-7:] + "_" # to understand n-gram breakdown: + '_'	
			ngrams.append(ngram_string)
		benign_ngram_model[entry] = {'name' : entry, 'binary_strings' : ngrams}

	# create x-gram (x goes from 2 to 8) for malicious data examples:
	malicious_ngram_model = {}
	for entry in malicious_asm_data:
		# create n-grams of opcodes:
		ngrams = []
		for y in range(len(malicious_asm_data[entry]['binary_strings']) - ngram_size + 1):
			subset = malicious_asm_data[entry]['binary_strings'][y:y+ngram_size]
			ngram_string = str()
			for s in subset:
				ngram_string += s[-7:] + "_" # to understand n-gram breakdown: + '_'	
			ngrams.append(ngram_string)
		malicious_ngram_model[entry] = {'name' : entry, 'binary_strings' : ngrams}
	return benign_ngram_model, malicious_ngram_model

def runAIS(N):
	global malware_string_mapping

	benign_data_dir = '/home/farhathz/riscv-malware-analysis/AIS_experiments/benign_asm-binary'
	malicious_data_dir = '/home/farhathz/riscv-malware-analysis/AIS_experiments/malware_asm-binary'

	ngram_size = N

	benign_asm_data, benign_asm_file_names, malicious_asm_data, malicious_asm_file_names = loadData(benign_data_dir, malicious_data_dir)
	benign_ngram_model, malicious_ngram_model = createNgram(benign_asm_data, malicious_asm_data, ngram_size)

	performance_all_trials = []

	num_trials = 100

	# perform 5 times 2-fold cross validation:
	for i in range(num_trials):
		# first, split the data into two halves for training and testing:
		training_malicious, training_benign, testing_malicious, testing_benign = None, None, None, None

		# make copy of original order of files and shuffle them around:
		copy_benign = list(benign_asm_file_names)
		copy_malicious = list(malicious_asm_file_names)

		random.shuffle(copy_benign); random.shuffle(copy_malicious)

		# make the split into training and testing:

		# train_split = int(len(copy_malicious)/2) # - for 5 times 2-fold cross validation
		train_split = int(len(copy_malicious) * 0.9) # - for 10-fold cross validation
	
		if use_ngrams:
			training_malicious = [malicious_ngram_model[X] for X in copy_malicious[:train_split] ]   
			testing_malicious = [malicious_ngram_model[X] for X in copy_malicious[train_split:] ]	

			training_benign = [benign_ngram_model[X] for X in copy_benign[:int(len(copy_benign)-len(testing_malicious))] ]   
			testing_benign = [benign_ngram_model[X] for X in copy_benign[int(len(copy_benign)-len(testing_malicious)):] ]	

		else:
			training_malicious = [malicious_asm_data[X] for X in copy_malicious[:train_split] ]   
			testing_malicious = [malicious_asm_data[X] for X in copy_malicious[train_split:] ]	

			training_benign = [benign_asm_data[X] for X in copy_benign[:int(len(copy_benign)-len(testing_malicious))] ]   
			testing_benign = [benign_asm_data[X] for X in copy_benign[int(len(copy_benign)-len(testing_malicious)):] ]	

		ais_model = AIS_NegativeSelection()
		
		#print('data overview:')
		#print(' - training malicious examples\t:-\t' + str(len(training_malicious)))
		#print(' - training benign examples\t:-\t' + str(len(training_benign)))
		#print(' - testing malicious examples\t:-\t' + str(len(testing_malicious)))
		#print(' - testing benign examples\t:-\t' + str(len(testing_benign)))

		# begin training phase:
		#print('\n------------------------------------------------------------------\n')
		#print('TRIAL ' + str(i) + ': beginning training process...')

		#for T in tqdm.tqdm(training_benign, desc='Building self set...'):
		for T in training_benign:		
			ais_model.buildSelfSet(T)
			
		#for T in tqdm.tqdm(training_malicious, desc='Building detector set...'):
		for T in training_malicious:		
			ais_model.buildDetectorSet(T)

		#print('\nself_set size = ' + str(len(ais_model.self_set)))
		#print('detector_set size = ' + str(len(ais_model.detector_set)))
		#print('\nTRIAL ' + str(i) + ': beginning testing process...')

		# here, positive means malicious / malware, negative means benign:		
		total_FP, total_FN, total_TP, total_TN = 0, 0, 0, 0
		total_negative = len(testing_benign)
		total_positive = len(testing_malicious)
		
		#for T in tqdm.tqdm(testing_benign, desc='Testing on benign examples...'):
		for T in testing_benign:
			# function returns True if there is a match in detector set:
			# - this means that for a benign example, we found a false positive detection
			# - if False, then it is a true negative, as it should truly be a negative detection
			# - if -1, then this sample cannot be counted (due to having no n-grams)
			if ais_model.testForAnomaly(T) == 1:
				total_FP += 1
			elif ais_model.testForAnomaly(T) == 0:
				total_TN += 1
			else:
				# this is when we have an issue detecting a certain file:
				total_negative -= 1

		#for T in tqdm.tqdm(testing_malicious, desc='Testing on malicious examples...'):
		for T in testing_malicious:
			# function returns True if there is a match in detector set:
			# - this means that for a malicious example, we found a positive detection
			# - if False, then it is a false negative, as it should be positive
			# - if -1, then this sample cannot be counted (due to having no n-grams)
			if ais_model.testForAnomaly(T) == 1:
				total_TP += 1
			elif ais_model.testForAnomaly(T) == 0:
				total_FN += 1
			else:
				# this is when we have an issue detecting a certain file:
				total_positive -= 1
		
		correctly_classified = float(total_TP + total_TN) * 100 / (float(total_positive + total_negative))
		incorrectly_classified = float(total_FP + total_FN) * 100 / (float(total_positive + total_negative))

		performance_all_trials.append( [correctly_classified, incorrectly_classified, total_positive + total_negative] )

		#print('\nTP\t:\t' + str(total_TP))
		#print('FP\t:\t' + str(total_FP))
		#print('TN\t:\t' + str(total_TN))
		#print('FN\t:\t' + str(total_FN))

		#print('\nPERCENT CORRECTLY CLASSIFIED\t:\t' + str(correctly_classified) + '%')
		#print('PERCENT INCORRECTLY CLASSIFIED\t:\t' + str(incorrectly_classified) + '%')

		#print('\n------------------------------------------------------------------\n')

		# writing strings to the file in addition to their source file:
		malware_string_file = open('malware_strings' + '-ngram=' + str(ngram_size) + '-trial-' + str(i) + '.txt', 'w')
		for K in malware_string_mapping:
			malware_string_file.write(str(K) + '\t' + str(malware_string_mapping[K]) + '\n')
		malware_string_file.close()
		
		malware_string_mapping = {}

	avg_correctly_classified, avg_incorrectly_classified, avg_size = 0.0, 0.0, 0.0
	for R in performance_all_trials:
		avg_correctly_classified += R[0]
		avg_incorrectly_classified += R[1]
		avg_size += R[2]
	
	avg_correctly_classified /= num_trials
	avg_incorrectly_classified /= num_trials
	avg_size /= num_trials

	print('** NGRAM ' + str(ngram_size) + ' -- AVERAGE PERCENT CORRECTLY CLASSIFIED\t:\t' + str(avg_correctly_classified) + '%')
	print('** NGRAM ' + str(ngram_size) + ' -- AVERAGE PERCENT INCORRECTLY CLASSIFIED\t:\t' + str(avg_incorrectly_classified) + '%')
	print('** NGRAM ' + str(ngram_size) + ' -- number of tested examples = ' + str(int(avg_size)) + '\n')
	
	return [avg_correctly_classified, avg_incorrectly_classified]
#end

if __name__ == '__main__':
	results = []
	for i in range(2,11):
		trial_result = runAIS(i)
	#	results.append(trial_result)

	#for i in range(len(results)):
	#	print('NGRAM ' + str(i) + ' : correct -- ' + str(results[i][0]) + '% , incorrect -- ' + str(results[i][1]) + '%')
