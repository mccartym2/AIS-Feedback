import sys, os, random, math, time, itertools

from rich.console import Console
from rich.table import Table

trial_count = 0

malware_string_mapping = {}

malware_detectors_hit_count = {}

true_negative_hit_count = {}

detector_size = 10

# options for detection:
use_ngrams = True
string_match_method = "whole"

ngram_size = 0

# number of detectors to keep for subset detector:
subset_size = 64
class_boundary = 0.30

possible_opcodes = [
	'0110111',
	'0010111',
	'1101111',
	'1100111',
	'1100011',
	'0110011',
	'0001111',
	'1110011',
	'0000011',
	'0100011',
	'0010011',
	'0011011',
	'0111011',
	'0101111',
	'0000111',
	'0100111',
	'1000111',
	'1001011',
	'1001111',
	'1010011',
	'1000011']


class AIS_NegativeSelection(object):
	# constructor method:
	def __init__(self):
		# NOTE: self_set -- set of benign strings, detector_set -- set of malicious strings
		self.self_set = set()
		self.detector_set = set()
		self.detector_subset = set()
		self.opcode_length = 7

	def setSubset(self, S):
		self.detector_subset = set(S) if len(S) > 0 else set()

	def getSize(self):
		return len(self.detector_set)

	def buildSelfSet(self, sample):
		# take each string from a benign example and add to self set:
		for string in sample['binary_strings']:
			self.self_set.add(string)

	def buildDetectorSet(self, sample, string_match_method="whole"):
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

		# print('Detector set: ' + str(self.detector_set))
				#endif	
		# print(malware_string_mapping)			

	def findMatchesInDetectorSet(self, sample, threshold=None):
		if string_match_method == 'partial' and threshold != None:
			return self.findMatchesInDetectorSet_partial(sample,threshold)
		return self.findMatchesInDetectorSet_whole(sample)

	def findMatchesInDetectorSet_whole(self, sample):
		found_strings = {}

		if len(sample['binary_strings']) == 0:
			return found_strings

		for string in sample['binary_strings']:
			if string in self.detector_set:
				if string in found_strings:
					pass
					# we give more weight to a string if it is seen more often in a sample:
					#found_strings[string] += 1
				else:
					found_strings[string] = 1

		return found_strings
	
	def falseNegativeStringsSet(self, sample, false_negative_strings):

		if len(sample['binary_strings']) == 0:
			return false_negative_strings

		for string in sample['binary_strings']:
			if string in false_negative_strings:
				false_negative_strings[string] += 1
			else:
				false_negative_strings[string] = 1

		return false_negative_strings

	def findMatchesInDetectorSet_partial(self, sample, threshold):
		found_strings = {}

		if len(sample['binary_strings']) == 0:
			return found_strings

		# calculate maximum allowed don't-cares (i.e. number of opcodes to not match):
		permitted_dont_cares = int(round((threshold) * ngram_size))	

		for string in sample['binary_strings']:
			string1_parts = string.split('_')
			for antibody in self.detector_set:
				string2_parts = antibody.split('_')

				hamming_distance = 0
				for N in range(ngram_size):
					if string1_parts[N] == string2_parts[N]:
						continue			
					hamming_distance += 1
			
				if hamming_distance <= permitted_dont_cares:
					if antibody in found_strings:
						found_strings[antibody] += 1
					else:
						found_strings[antibody] = 1
					break

		return found_strings
			
	def testForAnomaly(self, sample, malicious_sample, string_match_method="whole", use_subset=False, threshold=0.75):
		if string_match_method == "whole":
			return self.testForAnomaly_wholeMatch(sample, malicious_sample, use_subset=use_subset)
		return self.testForAnomaly_partialMatch(sample, malicious_sample, threshold=threshold, use_subset=use_subset)

	def testForAnomaly_wholeMatch(self, sample, malicious_sample, use_subset=False):
		if len(sample['binary_strings']) == 0:
			return -1, None		

		global class_boundary, malware_detectors_hit_count, true_negative_hit_count, malware_detectors_hit_count

		# measure number of n-grams that the sample is made of; this is used to measure percentage of detector hits:		
		total_ngrams = len(sample['binary_strings'])

		# sometimes, percentage-based may give 0, so this will make it default to 1:
		required_hits = round(total_ngrams * class_boundary) if round(total_ngrams * class_boundary) > 0 else 1

		# count number of hits each string in sample matches to used detector set:
		hit_count = 0	

		for string in sample['binary_strings']:
			if use_subset:
				# use only the detector subset:
				if string in self.detector_subset:
					hit_count += 1
					if not malicious_sample:
						if not string in malware_detectors_hit_count:
							malware_detectors_hit_count[string] = 1
						else:
							malware_detectors_hit_count[string] += 1
			else:
				# use entire detector set:
				if string in self.detector_set:
					hit_count += 1
					if malicious_sample:
						if not string in malware_detectors_hit_count:
							malware_detectors_hit_count[string] = 1
						else:
							malware_detectors_hit_count[string] += 1

		if hit_count == 0: 
			if not string in true_negative_hit_count:
				true_negative_hit_count[string] = 1
			else:
				true_negative_hit_count[string] += 1

			#if hit_count >= required_hits:
				#print(string)
				#return 1, [float(hit_count / total_ngrams), hit_count, required_hits]

		# if we are using detector subset, then we can just check for a single match:
		#if use_subset:
		#	return 1 if count > 0 else 0		

		# if we are using entire detector set, then we can check if there is a bit more significant overlap:		
		if hit_count >= required_hits:
			return 1, [float(hit_count / total_ngrams), hit_count, required_hits]
		return 0, [float(hit_count / total_ngrams), hit_count, required_hits]


	def testForAnomaly_partialMatch(self, sample, malicious_sample, use_subset=False, threshold=0.75):
		# print("testForAnomaly_partialMatch")
		if len(sample['binary_strings']) == 0:
			return -1, None

		# get total number of opcodes (n-gram size):
		global ngram_size, class_boundary	

		if use_subset:
			selected_detectors = self.detector_subset
		else:
			selected_detectors = self.detector_set	 
	
		# calculate maximum allowed don't-cares (i.e. number of opcodes to not match):
		permitted_dont_cares = int(math.floor((threshold) * ngram_size))		

		# measure number of n-grams that the sample is made of; this is used to measure percentage of detector hits:		
		total_ngrams = len(sample['binary_strings'])

		# sometimes, percentage-based may give 0, so this will make it default to 1:
		required_hits = round(total_ngrams * class_boundary) if round(total_ngrams * class_boundary) > 0 else 1
		
		# count number of hits each string in sample matches to used detector set:
		hit_count = 0

		for s_1 in range(total_ngrams):
			string1_parts = sample['binary_strings'][s_1].split('_')

			for s_2 in selected_detectors:
				string2_parts = s_2.split('_')

				hamming_distance = 0
				flag = False
				for N in range(ngram_size):
					if string1_parts[N] != string2_parts[N]:
						hamming_distance += 1

					# if we already are over permitted number of don't-cares, end:
					if hamming_distance > permitted_dont_cares:
						flag = True
						break

				if not flag:
					# we found a match for the string s_1, so no need to keep checking for this in detector set:
					hit_count += 1

					# check to see if we can stop searching early:
					if hit_count >= required_hits:
						return 1, float(hit_count / total_ngrams)
					break

		#if hit_count >= required_hits:
		#	return 1, float(hit_count / total_ngrams)
		return 0, float(hit_count / total_ngrams)
#enddef

def chunkstring(string, length):
    return (string[0+i:length+i] for i in range(0, len(string), length))
	
def loadData(benign_data_dir, malicious_data_dir):
	# Build dictionary with format:	
	#	{"file_1" : {"binary_strings" : [xxxxxxxx, xxxxxxxx, xxxxxxx ... ], "class" : 1 (benign) / 2 (malicious) }, ... }

	if benign_data_dir:
		# read and extract benign file data:
		benign_asm_data = {}; benign_asm_file_names = []
		for file in os.listdir(benign_data_dir):
			binary_strings = []

			# open the contents of the binary file:
			binary_asm_file = open(os.path.join(benign_data_dir, file), 'r'); lines = binary_asm_file.readlines()
			for L in lines:
				# read each binary string in the file and remove trailing new-line (\n) using rstrip():
				binary_string = L.rstrip()
				# check if the string is not 'nop' instruction:		
				#if binary_string is not '00000000000000000000000000010011':
				binary_strings.append(binary_string)	

			benign_asm_data[str(file)] = {"name" : str(file), "binary_strings" : binary_strings, "class" : 1}
			benign_asm_file_names.append(str(file))

	if malicious_data_dir:
		# read and extract malicious file data:
		malicious_asm_data = {}; malicious_asm_file_names = []
		for file in os.listdir(malicious_data_dir):
			binary_strings = []

			# open the contents of the binary file:
			binary_asm_file = open(os.path.join(malicious_data_dir,file), 'r'); lines = binary_asm_file.readlines()
			for L in lines:
				# read each binary string in the file and remove trailing new-line (\n) using rstrip():
				binary_string = L.rstrip()
				# check if the string is not 'nop' instruction:		
				#if binary_string is not '00000000000000000000000000010011':
				binary_strings.append(binary_string)	

			malicious_asm_data[str(file)] = {"name" : str(file), "binary_strings" : binary_strings, "class" : 2}
			malicious_asm_file_names.append(str(file))

	return benign_asm_data, benign_asm_file_names, malicious_asm_data, malicious_asm_file_names

def createNgram(benign_asm_data, malicious_asm_data,  ngram_size):
	benign_ngram_model, malicious_ngram_model = {}, {}

	max_num_ngrams = 0
	max_file_name = ''

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
		
		if len(ngrams) > max_num_ngrams:
			max_num_ngrams = len(ngrams)		
			max_file_name = entry		

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

		if len(ngrams) > max_num_ngrams:
			max_num_ngrams = len(ngrams)		
			max_file_name = entry		

	#print('Maximum number of n-gram strings: ' + str(max_num_ngrams) + ' (found in ' + max_file_name + ')')

	return benign_ngram_model, malicious_ngram_model

def save_ngrams_to_file(benign_set, malicious_set):
	ngrams_file = open('all_ngrams-ngram_size='  + str(ngram_size) + '.txt', 'w')
	for N in benign_set:
		for string in benign_set[N]['binary_strings']:
			ngrams_file.write(string + '\t' + '0\n')
	for N in malicious_set:
		for string in malicious_set[N]['binary_strings']:
			ngrams_file.write(string + '\t' + '1\n')
	ngrams_file.close()

	return

def run_AIS(method='NSA', percent_dont_care=0.50):
	global malware_string_mapping, ngram_size, class_boundary

	benign_data_dir = '/home/ubuntu/courses/691/AIS-Feedback/Datasets/benign_asm-binary'
	malicious_data_dir = '/home/ubuntu/courses/691/AIS-Feedback/Datasets/malware-asm_binary_botnet'

	benign_asm_data, benign_asm_file_names, malicious_asm_data, malicious_asm_file_names = loadData(benign_data_dir, malicious_data_dir)
	benign_ngram_model, malicious_ngram_model = createNgram(benign_asm_data, malicious_asm_data, ngram_size)

	performance_all_trials = {}

	num_trials = 200
    # Set the number of trial 
	#num_trials = 1

	frequency_string_matches = {}

	# train_split = int(len(copy_malicious)/2) # - for 5 times 2-fold cross validation
	train_split = int(len(malicious_asm_file_names) * 0.9) # - for 10-fold cross validation

	total_training_samples = 0
	for T in benign_ngram_model:		
		total_training_samples += len(benign_ngram_model[T]['binary_strings'])
	for T in malicious_ngram_model:		
		total_training_samples += len(malicious_ngram_model[T]['binary_strings'])
	#print('ngram=' + str(ngram_size) + ' - total number of samples: ' + str(total_training_samples))
	
	# save all ngrams for benign and malicious files to a json file:
	#import json
	#json.dump(benign_ngram_model, open('ngrams_all_benign_files-ngram='  + str(ngram_size) + '.json', 'w'))
	#json.dump(malicious_ngram_model, open('ngrams_all_malicious_files-ngram='  + str(ngram_size) + '.json', 'w'))

	# use this function to save all ngrams for both benign and malicious datasets:	
	#save_ngrams_to_file(benign_ngram_model, malicious_ngram_model)

	opcodes_to_match = (str(ngram_size - int(math.floor((percent_dont_care) * ngram_size))) if string_match_method == 'partial' else str(ngram_size)) + '|' + str(ngram_size)

	results_file = open('predictions_vs_groundtruth-ngram_size=' + str(ngram_size) + '-boundary=' + str(class_boundary) + '-opcodes_to_match=' + str(opcodes_to_match) + '-entire_set.csv','w')
	results_file.write('trial,label,prediction,groundtruth,percent_hits,class_boundary\n')

	# perform 5 times 2-fold cross validation:
	for i in range(num_trials):
		# first, split the data into two halves for training and testing:
		training_malicious, training_benign, testing_malicious, testing_benign = None, None, None, None

		whole_false_negative_strings = {}

		# make copy of original order of files and shuffle them around:
		copy_benign = list(benign_asm_file_names)
		copy_malicious = list(malicious_asm_file_names)

		random.shuffle(copy_benign); random.shuffle(copy_malicious)

		# make the split into training and testing:	
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
				
	##################################################################
	######################### TRAINING PHASE #########################
	##################################################################

		ais_model = AIS_NegativeSelection()
		for T in training_benign:		
			ais_model.buildSelfSet(T)
			
		for T in training_malicious:		
			ais_model.buildDetectorSet(T)

		#print('data overview:')
		#print(' - training malicious examples\t:-\t' + str(len(training_malicious)))
		#print(' - training benign examples\t:-\t' + str(len(training_benign)))
		#print(' - testing malicious examples\t:-\t' + str(len(testing_malicious)))
		#print(' - testing benign examples\t:-\t' + str(len(testing_benign)))

	##################################################################
	############### TESTING: WHOLE DETECTOR SET ######################
	##################################################################

		#print('\n------------------------------------------------------------------\n')
		#print('TRIAL ' + str(i) + ': beginning training process...')
		#print('\nself_set size = ' + str(len(ais_model.self_set)))
		#print('detector_set size = ' + str(len(ais_model.detector_set)))
		#print('\nTRIAL ' + str(i) + ': beginning testing process...')

		# here, positive means malicious / malware, negative means benign:		
		total_FP, total_FN, total_TP, total_TN = 0, 0, 0, 0
		fb_total_FP, fb_total_FN, fb_total_TP, fb_total_TN = 0, 0, 0, 0
		# total_FP_Name, total_FN_Name = [], []
		total_negative_samples = len(testing_benign)
		total_positive_samples = len(testing_malicious)
		fb_total_negative_samples = len(testing_benign)
		fb_total_positive_samples = len(testing_malicious)			

		avg_benign_ratio = 0.0
		avg_malicious_ratio = 0.0
		fb_avg_benign_ratio = 0.0
		fb_avg_malicious_ratio = 0.0
	
		#start = time.time()
		#for T in tqdm.tqdm(testing_benign, desc='Testing on benign examples...'):

		for T in testing_benign:
			# function returns True if there is a match in detector set:
			# - this means that for a benign example, we found a false positive detection
			# - if False, then it is a true negative, as it should truly be a negative detection
			# - if -1, then this sample cannot be counted (due to having no n-grams)

			# - prediction: 0 (benign), 1 (malicious), -1 (invalid sample)
			# - percent_detector_hits: % malicious string hits in sample or None (if invalid sample) 
			prediction, percent_detector_hits = ais_model.testForAnomaly(T, False, string_match_method=string_match_method, threshold=percent_dont_care)			

			if prediction == -1:
				# this is when we have an issue detecting a certain file:
				#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
				total_negative_samples -= 1
			else:
				# this file has sufficient lines for this n-gram size:
				if prediction == 1:
					total_FP += 1
				elif prediction == 0:
					total_TN += 1
				#print('ben: ' + str(percent_detector_hits))

				# we will keep track of the % of malicious strings (hits in the detector set) found in the sample T:
				avg_benign_ratio += percent_detector_hits[0]

				results_file.write(str(i) + ',' + 'benign' + ',' + str(prediction) + ',' + str(0) + ',' + str(percent_detector_hits[0]) + ',' + str(class_boundary) + '\n')

		# print(str(dict(sorted(malware_detectors_hit_count.items()))))
		sorted_dict = dict(reversed(sorted(malware_detectors_hit_count.items(), key=lambda item: item[1])))
		out = dict(itertools.islice(sorted_dict.items(), detector_size)).keys()

		# print(out)
		#for T in tqdm.tqdm(testing_malicious, desc='Testing on malicious examples...'):
		for T in testing_malicious:
			# function returns True if there is a match in detector set:
			# - this means that for a malicious example, we found a positive detection
			# - if False, then it is a false negative, as it should be positive
			# - if -1, then this sample cannot be counted (due to having no n-grams)

			# - prediction: 0 (benign), 1 (malicious), -1 (invalid sample)
			# - percent_detector_hits: % malicious string hits in sample or None (if invalid sample)
			prediction, percent_detector_hits = ais_model.testForAnomaly(T, True, string_match_method=string_match_method, threshold=percent_dont_care)			

			if prediction == -1:
				# this is when we have an issue detecting a certain file:
				#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
				total_positive_samples -= 1
			else:
				if prediction == 1:
					total_TP += 1
				elif prediction == 0:
					total_FN += 1
					whole_false_negative_strings = ais_model.falseNegativeStringsSet(T, whole_false_negative_strings)

				#print('mal: ' + str(percent_detector_hits))

				# we will keep track of the % of malicious strings (hits in the detector set) found in the sample T:
				avg_malicious_ratio += percent_detector_hits[0]

				results_file.write(str(i) + ',' + 'malicious' + ',' + str(prediction) + ',' + str(1) + ',' + str(percent_detector_hits[0]) + ',' + str(class_boundary) + '\n')

			found_strings = ais_model.findMatchesInDetectorSet(T, percent_dont_care) 
			for S in found_strings:
				if S in frequency_string_matches:
					frequency_string_matches[S] += found_strings[S]
				else:
					frequency_string_matches[S] = found_strings[S]

		sorted_false_negative_strings = dict(reversed(sorted(whole_false_negative_strings.items(), key=lambda item: item[1])))

		# Run Feedback loop
		detector_4th_quantile = []
		detector_5th_quantile = []
		for detector in ais_model.detector_set:
			detector_string_quantile_test = str(detector.replace("_", ""))
			detector_4th_quantile = detector_4th_quantile + [ str('_' + detector_string_quantile_test[0:27]), str('_' + detector_string_quantile_test[7:35]) + '_', str(detector_string_quantile_test[14:42] + '_')]
			detector_5th_quantile = detector_5th_quantile + [ str('_' + detector_string_quantile_test[0:34]), str(detector_string_quantile_test[7:42] + '_')]

		detector_4th_quantile = list(set(detector_4th_quantile))
		detector_5th_quantile = list(set(detector_5th_quantile))

		matching_4 = []
		matching_5 = []
		for false_negative_string in sorted_false_negative_strings:
			result = False
			false_negative_test = false_negative_string.replace("_", "")

			test = [ str('_' + false_negative_test[0:34]), str(false_negative_test[7:42] + '_')]
			result = not set(test).isdisjoint(detector_5th_quantile)
			if(result):
				matching_5.append(false_negative_string)
				continue

			test = [ str('_' + false_negative_test[0:27]), str('_' + false_negative_test[7:35]) + '_', str(false_negative_test[14:42] + '_')]
			result = not set(test).isdisjoint(detector_4th_quantile)
			if(result):
				matching_4.append(false_negative_string)

		# test feeback changes
  
		tmp_detector = ais_model.detector_set 

		ais_model.detector_set = list(ais_model.detector_set) + matching_5

		for T in testing_benign:
			prediction, percent_detector_hits = ais_model.testForAnomaly(T, False, string_match_method=string_match_method, use_subset=False, threshold=percent_dont_care)			

			if prediction == -1:
				# this is when we have an issue detecting a certain file:
				#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
				fb_total_negative_samples -= 1
			else:
				if prediction == 1:
					fb_total_FP += 1
				elif prediction == 0:
					fb_total_TN += 1

				fb_avg_benign_ratio += percent_detector_hits[0]
						
		for T in testing_malicious:
			prediction, percent_detector_hits = ais_model.testForAnomaly(T, True, string_match_method=string_match_method, use_subset=False, threshold=percent_dont_care)			
			
			if prediction == -1:
				# this is when we have an issue detecting a certain file:
				#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
				fb_total_positive_samples -= 1
			else:
				if prediction == 1:
					fb_total_TP += 1
				elif prediction == 0:
					fb_total_FN += 1

				fb_avg_malicious_ratio += percent_detector_hits[0]

		#print(time.time() - start)
		# saving results in dictionary:
		results = {}
		results['TP'] = total_TP		
		results['FP'] = total_FP		
		results['TN'] = total_TN		
		results['FN'] = total_FN
		results['FBTP'] = fb_total_TP		
		results['FBFP'] = fb_total_FP		
		results['FBTN'] = fb_total_TN	
		results['FBFN'] = fb_total_FN			

		# calculate different metrics (based on https://en.wikipedia.org/wiki/F-score):
		# - true positive rate (recall, sensitivity, hit rate)		
		results['TPR'] = 100.0 * (total_TP / float(total_TP + total_FN))
		results['FBTPR'] = 100.0 * (fb_total_TP / float(fb_total_TP + fb_total_FN))
		# - false negative rate (miss rate)
		results['FNR'] = 100.0 - results['TPR']
		results['FBFNR'] = 100.0 - results['FBTPR']
		# - true negative rate (specificity)
		results['TNR'] = 100.0 * (total_TN / float(total_TN + total_FP))
		results['FBTNR'] = 100.0 * (fb_total_TN / float(fb_total_TN + fb_total_FP))
		# - false positive rate (fall-out)
		results['FPR'] = 100.0 - results['TNR']
		results['FBFPR'] = 100.0 - results['FBTNR']
		# - positive predictive value (precision)
		try:
			# - positive predictive value (precision)
			results['PPV'] = 100.0 * (total_TP / float(total_TP + total_FP))
		except ZeroDivisionError:
			results['PPV'] = 0.0
		
		# - accuracy - number of true detections (i.e. true positive and true negative)
		results['accuracy'] = float(total_TP + total_TN) * 100.0 / (float(total_positive_samples + total_negative_samples))
		results['fb_accuracy'] = float(fb_total_TP + fb_total_TN) * 100.0 / (float(fb_total_positive_samples + fb_total_negative_samples))

		# F1 score
		results['F1 score'] = 100.0 * (2.0 * total_TP / float( (2.0 * total_TP) + total_FP + total_FN))
		results['fb_F1_score'] = 100.0 * (2.0 * fb_total_TP / float( (2.0 * fb_total_TP) + fb_total_TP + fb_total_FN))

		#input(results['accuracy'])

		# hit ratio - average ratio of malicious strings (detector hits) to total number of strings:
		results['benign-hit_ratio'] = avg_benign_ratio / total_negative_samples	
		results['malicious-hit_ratio'] = avg_malicious_ratio / total_positive_samples
		results['fb_benign-hit_ratio'] = fb_avg_benign_ratio / fb_total_negative_samples	
		results['fb_malicious-hit_ratio'] = fb_avg_malicious_ratio / fb_total_positive_samples

		results['num_samples'] = total_positive_samples + total_negative_samples
		results['fb_num_samples'] = fb_total_positive_samples + fb_total_negative_samples
		results['fb_num_detectors'] = len(ais_model.detector_set)

		ais_model.detector_set = tmp_detector
		results['num_detectors'] = len(ais_model.detector_set)

		performance_all_trials[str('trial_' + str(i))] = results

		# writing strings to the file in addition to their source file:
		#if i == 100: # only write 101th trial data for demo
		#	malware_string_file = open('malware_strings' + '-ngram=' + str(ngram_size) + '-trial-' + str(i) + '.txt', 'w')
		#	for K in malware_string_mapping:
		#		malware_string_file.write(str(K) + '\t' + str(malware_string_mapping[K]) + '\n')
		#	malware_string_file.close()
		#
		#malware_string_mapping = {}

	results_file.close()

	# compute average metrics over all trials:
	performance_all_detectors = {}
	performance_all_detectors['accuracy'] = 0.0
	performance_all_detectors['F1 score'] = 0.0
	performance_all_detectors['TPR'] = 0.0
	performance_all_detectors['FPR'] = 0.0
	performance_all_detectors['TNR'] = 0.0
	performance_all_detectors['FNR'] = 0.0
	performance_all_detectors['benign-hit_ratio'] = 0.0
	performance_all_detectors['malicious-hit_ratio'] = 0.0
	performance_all_detectors['fb_accuracy'] = 0.0
	performance_all_detectors['fb_F1_score'] = 0.0
	performance_all_detectors['FBTPR'] = 0.0
	performance_all_detectors['FBFPR'] = 0.0
	performance_all_detectors['FBTNR'] = 0.0
	performance_all_detectors['FBFNR'] = 0.0
	performance_all_detectors['fb_benign-hit_ratio'] = 0.0
	performance_all_detectors['fb_malicious-hit_ratio'] = 0.0
		
	average_num_samples, average_num_detectors = 0.0, 0.0
	fb_average_num_samples, fb_average_num_detectors = 0.0, 0.0
		
	for trial in performance_all_trials:
		performance_all_detectors['accuracy'] += performance_all_trials[trial]['accuracy']
		performance_all_detectors['F1 score'] += performance_all_trials[trial]['F1 score']
		performance_all_detectors['TPR'] += performance_all_trials[trial]['TPR']
		performance_all_detectors['FPR'] += performance_all_trials[trial]['FPR']
		performance_all_detectors['TNR'] += performance_all_trials[trial]['TNR']
		performance_all_detectors['FNR'] += performance_all_trials[trial]['FNR']
		performance_all_detectors['fb_accuracy'] += performance_all_trials[trial]['fb_accuracy']
		performance_all_detectors['fb_F1_score'] += performance_all_trials[trial]['fb_F1_score']
		performance_all_detectors['FBTPR'] += performance_all_trials[trial]['FBTPR']
		performance_all_detectors['FBFPR'] += performance_all_trials[trial]['FBFPR']
		performance_all_detectors['FBTNR'] += performance_all_trials[trial]['FBTNR']
		performance_all_detectors['FBFNR'] += performance_all_trials[trial]['FBFNR']
	
		# find overall average % of malware strings found in samples:
		performance_all_detectors['benign-hit_ratio'] += performance_all_trials[trial]['benign-hit_ratio']
		performance_all_detectors['malicious-hit_ratio'] += performance_all_trials[trial]['malicious-hit_ratio']
		performance_all_detectors['fb_benign-hit_ratio'] += performance_all_trials[trial]['fb_benign-hit_ratio']
		performance_all_detectors['fb_malicious-hit_ratio'] += performance_all_trials[trial]['fb_malicious-hit_ratio']
	
		average_num_samples += performance_all_trials[trial]['num_samples']
		average_num_detectors += performance_all_trials[trial]['num_detectors']
		fb_average_num_samples += performance_all_trials[trial]['fb_num_samples']
		fb_average_num_detectors += performance_all_trials[trial]['fb_num_detectors']
		
	average_num_detectors /= num_trials
	average_num_samples /= num_trials
	fb_average_num_detectors /= num_trials
	fb_average_num_samples /= num_trials

	performance_all_detectors['accuracy'] /= num_trials 
	performance_all_detectors['F1 score'] /= num_trials
	performance_all_detectors['TPR'] /= num_trials
	performance_all_detectors['FPR'] /= num_trials
	performance_all_detectors['TNR'] /= num_trials
	performance_all_detectors['FNR'] /= num_trials
	performance_all_detectors['benign-hit_ratio'] /= num_trials
	performance_all_detectors['malicious-hit_ratio'] /= num_trials		
	performance_all_detectors['num_detectors'] = int(average_num_detectors)
	performance_all_detectors['num_samples'] = int(average_num_samples)
	performance_all_detectors['class_boundary'] = class_boundary	
	performance_all_detectors['fb_accuracy'] /= num_trials 
	performance_all_detectors['fb_F1_score'] /= num_trials
	performance_all_detectors['FBTPR'] /= num_trials
	performance_all_detectors['FBFPR'] /= num_trials
	performance_all_detectors['FBTNR'] /= num_trials
	performance_all_detectors['FBFNR'] /= num_trials
	performance_all_detectors['fb_benign-hit_ratio'] /= num_trials
	performance_all_detectors['fb_malicious-hit_ratio'] /= num_trials		
	performance_all_detectors['fb_num_detectors'] = int(fb_average_num_detectors)
	performance_all_detectors['fb_num_samples'] = int(fb_average_num_samples)

	print('NGRAM SIZE = ' + str(ngram_size) + ':')
	print(' - algorithm : NSA' 	)
	print(' - string matching method : ' + string_match_method)	
	print(' - opcodes to match : ' + (str(ngram_size - int(math.floor((percent_dont_care) * ngram_size))) if string_match_method == 'partial' else str(ngram_size)) + '/' + str(ngram_size))	
	print(' - required % hits per sample : ' + str(class_boundary))	
	print(' - average number of tested examples = ' + str(int(average_num_samples)))
	print(' - average number of detectors = ' + str(int(average_num_detectors)))
	print(' - ENTIRE detector set results:')
	#print(' \t-- total unique strings seen = ' + str(len(frequency_string_matches)) )
	print(' \t-- AVG % CORRECTLY CLASSIFIED\t:      \t' + str(performance_all_detectors['accuracy']) + '%')
	print(' \t-- AVG % INCORRECTLY CLASSIFIED\t:    \t' + str(100.0 - performance_all_detectors['accuracy']) + '%\n')
	print(' - After feedback loop')
	print(' \t-- AVG % CORRECTLY CLASSIFIED\t:   \t' + str(performance_all_detectors['fb_accuracy']) + '%')
	print(' \t-- AVG % INCORRECTLY CLASSIFIED\t: \t' + str(100.0 - performance_all_detectors['fb_accuracy']) + '%\n')

	#print('BENIGN: % string hits in samples - ' + str(performance_all_detectors['benign-hit_ratio']) + '%')
	#print('MALICIOUS: % string hits in samples - ' + str(performance_all_detectors['malicious-hit_ratio']) + '%\n')
		
	##################################################################
	############### TESTING: DETECTOR SUBSET  ########################
	##################################################################
	
	# generate frequency report of malware strings:	
	sorted_freq_matches = []
	for S in frequency_string_matches:
		sorted_freq_matches.append([S, frequency_string_matches[S]])	

	# sort the strings by frequency of matches in testing:
	sorted_freq_matches.sort(key = lambda x: x[1], reverse=True)

	detected_strings_file = open('frequency_string_matches-method=' + ('CSA' if method == 'CSA' else 'NSA') + '-ngram=' + str(ngram_size) + '.csv', 'w')
	detected_strings_file.write('ngram' + ',' + 'hit_count' + '\n')
	for S in sorted_freq_matches:
		detected_strings_file.write(str(S[0]) + ',' + str(S[1]) + '\n')
	
	detected_strings_file.close()
	
	all_results = [performance_all_detectors]

	#class_boundary = 0.0 # making class boundary zero for subset detectors - this will mean at least one match is needed

	# trying different sizes of subsets:
	for SS in [len(sorted_freq_matches), 256, 128, 64, 32, 16, 8]:
		global subset_size
		subset_size = SS

		ais_model.setSubset([])	

		######## USE THE FREQUENCY TO DECIDE ON SUBSET: #######
		size = min(subset_size, len(sorted_freq_matches))	
		
		subset_freq_matches = [sorted_freq_matches[x][0] for x in range(size)]
		#print(len(subset_freq_matches))
		#input(subset_freq_matches)

		# save the top N strings:
		ais_model.setSubset(subset_freq_matches)

		results_file = open('predictions_vs_groundtruth-ngram_size=' + str(ngram_size) + '-boundary=' + str(class_boundary) + '-opcodes_to_match=' + str(opcodes_to_match) + '-subset=' + str(size) +'.csv','w')
		results_file.write('trial,label,prediction,groundtruth,percent_hits,class_boundary\n')

		for i in range(num_trials):
			# first, split the data into two halves for training and testing:
			training_malicious, training_benign, testing_malicious, testing_benign = None, None, None, None

			sub_false_negative_strings = {}

			# make copy of original order of files and shuffle them around:
			copy_benign = list(benign_asm_file_names)
			copy_malicious = list(malicious_asm_file_names)

			random.shuffle(copy_benign); random.shuffle(copy_malicious)

			# make the split into training and testing:
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

			# here, positive means malicious / malware, negative means benign:		
			total_FP, total_FN, total_TP, total_TN = 0, 0, 0, 0
			fb_total_FP, fb_total_FN, fb_total_TP, fb_total_TN = 0, 0, 0, 0
			total_negative_samples = len(testing_benign)
			total_positive_samples = len(testing_malicious)
			fb_total_negative_samples = len(testing_benign)
			fb_total_positive_samples = len(testing_malicious)
			
			#start = time.time()
			#for T in tqdm.tqdm(testing_benign, desc='Testing on benign examples...'):
			for T in testing_benign:
				# function returns True if there is a match in detector set:
				# - this means that for a benign example, we found a false positive detection
				# - if False, then it is a true negative, as it should truly be a negative detection
				# - if -1, then this sample cannot be counted (due to having no n-grams)

				# - prediction: 0 (benign), 1 (malicious), -1 (invalid sample)
				# - percent_detector_hits: % malicious string hits in sample or None (if invalid sample) 
				prediction, percent_detector_hits = ais_model.testForAnomaly(T, False, string_match_method=string_match_method, use_subset=True, threshold=percent_dont_care)			

				if prediction == -1:
					# this is when we have an issue detecting a certain file:
					#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
					total_negative_samples -= 1
				else:
					# this file has sufficient lines for this n-gram size:
					if prediction == 1:
						total_FP += 1
					elif prediction == 0:
						total_TN += 1

					results_file.write(str(i) + ',' + 'benign' + ',' + str(prediction) + ',' + str(0) + ',' + str(percent_detector_hits[0]) + ',' + str(class_boundary) + '\n')
							
			#for T in tqdm.tqdm(testing_malicious, desc='Testing on malicious examples...'):
			for T in testing_malicious:
				# function returns True if there is a match in detector set:
				# - this means that for a malicious example, we found a positive detection
				# - if False, then it is a false negative, as it should be positive
				# - if -1, then this sample cannot be counted (due to having no n-grams)

				# - prediction: 0 (benign), 1 (malicious), -1 (invalid sample)
				# - percent_detector_hits: % malicious string hits in sample or None (if invalid sample) 
				prediction, percent_detector_hits = ais_model.testForAnomaly(T, True, string_match_method=string_match_method, use_subset=True, threshold=percent_dont_care)			

				if prediction == -1:
					# this is when we have an issue detecting a certain file:
					#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
					total_positive_samples -= 1
				else:
					if prediction == 1:
						total_TP += 1
					elif prediction == 0:
						total_FN += 1
						sub_false_negative_strings = ais_model.falseNegativeStringsSet(T, sub_false_negative_strings)
					#input(sorted_freq_matches[0:size-1])	

					results_file.write(str(i) + ',' + 'malicious' + ',' + str(prediction) + ',' + str(1) + ',' + str(percent_detector_hits[0]) + ',' + str(class_boundary) + '\n')

			sorted_true_negative_dict = dict(reversed(sorted(true_negative_hit_count.items(), key=lambda item: item[1])))
			# print('sorted_true_negative_dict: ' + str(len(sorted_true_negative_dict)))
			out = dict(itertools.islice(sorted_dict.items(), detector_size)).keys()

			sorted_false_negative_strings = dict(reversed(sorted(sub_false_negative_strings.items(), key=lambda item: item[1])))
   
			detector_4th_quantile = []
			detector_5th_quantile = []
			for detector in ais_model.detector_subset:
				detector_string_quantile_test = str(detector.replace("_", ""))
				detector_4th_quantile = detector_4th_quantile + [ str('_' + detector_string_quantile_test[0:27]), str('_' + detector_string_quantile_test[7:35]) + '_', str(detector_string_quantile_test[14:42] + '_')]
				detector_5th_quantile = detector_5th_quantile + [ str('_' + detector_string_quantile_test[0:34]), str(detector_string_quantile_test[7:42] + '_')]

			detector_4th_quantile = list(set(detector_4th_quantile))
			detector_5th_quantile = list(set(detector_5th_quantile))

			matching_4 = []
			matching_5 = []
			for false_negative_string in sorted_false_negative_strings:
				result = False
				false_negative_test = false_negative_string.replace("_", "")

				test = [ str('_' + false_negative_test[0:34]), str(false_negative_test[7:42] + '_')]
				result = not set(test).isdisjoint(detector_5th_quantile)
				if(result):
					matching_5.append(false_negative_string)
					continue

				test = [ str('_' + false_negative_test[0:27]), str('_' + false_negative_test[7:35]) + '_', str(false_negative_test[14:42] + '_')]
				result = not set(test).isdisjoint(detector_4th_quantile)
				if(result):
					matching_4.append(false_negative_string)

			
			sub_tmp_detector = ais_model.detector_subset

			ais_model.detector_subset = list(ais_model.detector_subset) + matching_5

			for T in testing_benign:
				prediction, percent_detector_hits = ais_model.testForAnomaly(T, False, string_match_method=string_match_method, use_subset=True, threshold=percent_dont_care)			

				if prediction == -1:
					# this is when we have an issue detecting a certain file:
					#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
					fb_total_negative_samples -= 1
				else:
					if prediction == 1:
						fb_total_FP += 1
					elif prediction == 0:
						fb_total_TN += 1

					fb_avg_benign_ratio += percent_detector_hits[0]
							
			for T in testing_malicious:
				prediction, percent_detector_hits = ais_model.testForAnomaly(T, True, string_match_method=string_match_method, use_subset=True, threshold=percent_dont_care)			
				
				if prediction == -1:
					# this is when we have an issue detecting a certain file:
					#print(str(T['name']) + ' has fewer than ' + str(ngram_size) + ' lines')
					fb_total_positive_samples -= 1
				else:
					if prediction == 1:
						fb_total_TP += 1
					elif prediction == 0:
						fb_total_FN += 1

					fb_avg_malicious_ratio += percent_detector_hits[0]


			# out = dict(itertools.islice(sorted_dict.items(), detector_size)).keys()
			#print(time.time() - start)		
				
			# saving results in dictionary:
			results = {}
			results['TP'] = total_TP		
			results['FP'] = total_FP		
			results['TN'] = total_TN		
			results['FN'] = total_FN
			results['FBTP'] = fb_total_TP		
			results['FBFP'] = fb_total_FP		
			results['FBTN'] = fb_total_TN	
			results['FBFN'] = fb_total_FN		

			# calculate different metrics (based on https://en.wikipedia.org/wiki/F-score):
			# - true positive rate (recall, sensitivity, hit rate)		
			results['TPR'] = 100.0 * (total_TP / float(total_TP + total_FN))
			results['FBTPR'] = 100.0 * (fb_total_TP / float(fb_total_TP + fb_total_FN))
			# - false negative rate (miss rate)
			results['FNR'] = 100.0 - results['TPR']
			results['FBFNR'] = 100.0 - results['FBTPR']
			# - true negative rate (specificity)
			results['TNR'] = 100.0 * (total_TN / float(total_TN + total_FP))
			results['FBTNR'] = 100.0 * (fb_total_TN / float(fb_total_TN + fb_total_FP))
			# - false positive rate (fall-out)
			results['FPR'] = 100.0 - results['TNR']
			results['FBFPR'] = 100.0 - results['FBTNR']
			try:
				# - positive predictive value (precision)
				results['PPV'] = 100.0 * (total_TP / float(total_TP + total_FP))
			except ZeroDivisionError:
				results['PPV'] = 0.0
		
			# - accuracy - number of true detections (i.e. true positive and true negative)
			results['accuracy'] = float(total_TP + total_TN) * 100.0 / (float(total_positive_samples + total_negative_samples))
			results['fb_accuracy'] = float(fb_total_TP + fb_total_TN) * 100.0 / (float(fb_total_positive_samples + fb_total_negative_samples))

			# F1 score
			results['F1 score'] = 100.0 * (2.0 * total_TP / float( (2.0 * total_TP) + total_FP + total_FN))
			results['fb_F1_score'] = 100.0 * (2.0 * fb_total_TP / float( (2.0 * fb_total_TP) + fb_total_TP + fb_total_FN))

			# hit ratio - average ratio of malicious strings (detector hits) to total number of strings:
			results['benign-hit_ratio'] = avg_benign_ratio / total_negative_samples	
			results['malicious-hit_ratio'] = avg_malicious_ratio / total_positive_samples
			results['fb_benign-hit_ratio'] = fb_avg_benign_ratio / fb_total_negative_samples	
			results['fb_malicious-hit_ratio'] = fb_avg_malicious_ratio / fb_total_positive_samples

			results['num_samples'] = total_positive_samples + total_negative_samples
			results['fb_num_samples'] = fb_total_positive_samples + fb_total_negative_samples

			results['fb_num_detectors'] = len(ais_model.detector_subset)

			ais_model.detector_subset = sub_tmp_detector
			results['num_detectors'] = len(ais_model.detector_subset)


			performance_all_trials[str('trial_' + str(i))] = results

		results_file.close()

		# compute average metrics over all trials:
		performance_subset = {}
		performance_subset['accuracy'] = 0.0
		performance_subset['F1 score'] = 0.0
		performance_subset['TPR'] = 0.0
		performance_subset['FPR'] = 0.0
		performance_subset['TNR'] = 0.0
		performance_subset['FNR'] = 0.0
		performance_subset['benign-hit_ratio'] = 0.0
		performance_subset['malicious-hit_ratio'] = 0.0
		performance_subset['fb_accuracy'] = 0.0
		performance_subset['fb_F1_score'] = 0.0
		performance_subset['FBTPR'] = 0.0
		performance_subset['FBFPR'] = 0.0
		performance_subset['FBTNR'] = 0.0
		performance_subset['FBFNR'] = 0.0
		performance_subset['fb_benign-hit_ratio'] = 0.0
		performance_subset['fb_malicious-hit_ratio'] = 0.0
					
		average_num_samples = 0.0
		fb_average_num_samples = 0.0
			
		for trial in performance_all_trials:
			performance_subset['accuracy'] += performance_all_trials[trial]['accuracy']
			performance_subset['F1 score'] += performance_all_trials[trial]['F1 score']
			performance_subset['TPR'] += performance_all_trials[trial]['TPR']
			performance_subset['FPR'] += performance_all_trials[trial]['FPR']
			performance_subset['TNR'] += performance_all_trials[trial]['TNR']
			performance_subset['FNR'] += performance_all_trials[trial]['FNR']
			performance_subset['fb_accuracy'] += performance_all_trials[trial]['fb_accuracy']
			performance_subset['fb_F1_score'] += performance_all_trials[trial]['fb_F1_score']
			performance_subset['FBTPR'] += performance_all_trials[trial]['FBTPR']
			performance_subset['FBFPR'] += performance_all_trials[trial]['FBFPR']
			performance_subset['FBTNR'] += performance_all_trials[trial]['FBTNR']
			performance_subset['FBFNR'] += performance_all_trials[trial]['FBFNR']
		
			# find overall average % of malware strings found in samples:
			performance_subset['benign-hit_ratio'] += performance_all_trials[trial]['benign-hit_ratio']
			performance_subset['malicious-hit_ratio'] += performance_all_trials[trial]['malicious-hit_ratio']
			performance_subset['fb_benign-hit_ratio'] += performance_all_trials[trial]['fb_benign-hit_ratio']
			performance_subset['fb_malicious-hit_ratio'] += performance_all_trials[trial]['fb_malicious-hit_ratio']
		
			average_num_samples += performance_all_trials[trial]['num_samples']
			fb_average_num_samples += performance_all_trials[trial]['fb_num_samples']

		performance_subset['accuracy'] /= num_trials 
		performance_subset['F1 score'] /= num_trials
		performance_subset['TPR'] /= num_trials
		performance_subset['FPR'] /= num_trials
		performance_subset['TNR'] /= num_trials
		performance_subset['FNR'] /= num_trials
		performance_subset['benign-hit_ratio'] /= num_trials
		performance_subset['malicious-hit_ratio'] /= num_trials	
		performance_subset['num_samples'] = int(average_num_samples / num_trials)
		performance_subset['num_detectors'] = len(ais_model.detector_subset)
		performance_subset['class_boundary'] = class_boundary
		performance_subset['fb_accuracy'] /= num_trials 
		performance_subset['fb_F1_score'] /= num_trials
		performance_subset['FBTPR'] /= num_trials
		performance_subset['FBFPR'] /= num_trials
		performance_subset['FBTNR'] /= num_trials
		performance_subset['FBFNR'] /= num_trials
		performance_subset['fb_benign-hit_ratio'] /= num_trials
		performance_subset['fb_malicious-hit_ratio'] /= num_trials	
		performance_subset['fb_num_samples'] = int(fb_average_num_samples / num_trials)
		performance_subset['fb_num_detectors'] = len(ais_model.detector_subset)
		
		print(' - SUBSET detector set results:')
		if method == 'NSA':
			print(' \t-- size of detector subset (from history) = ' + str(len(ais_model.detector_subset)) )
		else:
			print(' \t-- size of detector subset = ' + str(len(ais_model.memory_subset)) )
		print(' \t-- AVG % CORRECTLY CLASSIFIED\t:\t' + str(performance_subset['accuracy']) + '%')
		print(' \t-- AVG % INCORRECTLY CLASSIFIED\t:\t' + str(100.0 - performance_subset['accuracy']) + '%')
		print(' - After feedback loop')
		print(' \t-- AVG % CORRECTLY CLASSIFIED\t:\t' + str(performance_subset['fb_accuracy']) + '%')
		print(' \t-- AVG % INCORRECTLY CLASSIFIED\t:\t' + str(100.0 - performance_subset['fb_accuracy']) + '%')

		print('\n------------------------------------------------------------------\n')
	
		all_results.append(performance_subset)

	return all_results
#end


if __name__ == '__main__':

	method = 'NSA'
	
	# Number of detectors to keep for subset detector
	subset_size = int(input('Number of detectors to keep for subset detector:').strip() or "64")

	for I in range(6,16):
		for D in [0.0]: # don't-care %s : 0.4% - 4/6, 0.2% - 5/6, 0.0% - 6/6 opcodes
			# save results from each n-gram size trial and don't-care:
			results = []

			start, stop, step = 1, 6, 1 # for whole, try boundaries 1% to 5%
			if D > 0:
				string_match_method = "partial"
				if D == 0.2:
					start, stop = 31, 35	# for partial, try boundaries between 25% and 35%
				else:
					start, stop = 35, 45	# for partial, try boundaries between 25% and 35%
			else:
				string_match_method = "whole"

			# go though different values of n-gram sizes based on i:
			ngram_size = I

			# percent_dont_care - % of opcodes to ignore when measuring similarity (20% / 0.2 worked best).
			percent_dont_care = D

			# compute number of opcodes to match based on current percent_dont_care:
			opcodes_to_match = (str(ngram_size - int(math.floor((percent_dont_care) * ngram_size))) if string_match_method == 'partial' else str(ngram_size)) + '|' + str(ngram_size)

			for T in range(start, stop, step):
				# trying different overlap values to see which is best:
				class_boundary = float(T / 100.0)			
				results.append( run_AIS(method, percent_dont_care) )
			#end

			# class_boundary = 0 - at least one detector hit should be observed:
			#class_boundary = 0.0	
			#results.append( run_AIS(method, percent_dont_care) )

			# save results to file:
			report_file = open('report-AIS_model=' + str(method) + '-opcodes_to_match=' + opcodes_to_match + '.csv', 'w')
			table = Table(title='report-AIS_model=' + str(method) + '-opcodes_to_match=' + opcodes_to_match )
			report_file.write('n-gram_size,opcodes_to_match,class_threshold,num_detectors,accuracy,TPR,FPR,TNR,FNR,F1_score\n')

			columns = ["n-gram_size", "opcodes_to_match", "class_threshold", "num_detectors", "TPR", "FPR", "TNR", "FNR", "F1_score", "accuracy","fb_accuracy"]
			for column in columns:
				table.add_column(column)

			lst = [] 

			for i in range(len(results)):
				for j in range(len(results[i])):
					lst.append([str(ngram_size), str(opcodes_to_match.replace('|', '/')),
				 				str(results[i][j]['class_boundary']),
								str(results[i][j]['num_detectors']),
								str(results[i][j]['TPR']), # True Positive Rate
								str(results[i][j]['FPR']), # False Positive Rate
								str(results[i][j]['TNR']), # True Negative Rate
								str(results[i][j]['FNR']), # False Negative Rate
								str(results[i][j]['F1 score']),
								str(results[i][j]['accuracy']),
								str(results[i][j]['fb_accuracy']),
								]) 
					# table.add_row([str(ngram_size), str(opcodes_to_match.replace('|', '/')), str(results[i][j]['class_boundary']), str(results[i][j]['num_detectors']), str(results[i][j]['TPR']), str(results[i][j]['TNR']), str(results[i][j]['F1 score'])], style='bright_green')
					report_file.write(	str(ngram_size) + ',' +  # ngram_size
								str(opcodes_to_match.replace('|', '/')) + ',' +  # opcodes_to_match
								str(results[i][j]['class_boundary']) + ',' +  # class_threshold
								str(results[i][j]['num_detectors']) + ',' + str(results[i][j]['accuracy']) + ',' + 
								str(results[i][j]['TPR']) + ',' + str(results[i][j]['FPR']) + ',' + 
								str(results[i][j]['TNR']) + ',' + str(results[i][j]['FNR']) + ',' +
								str(results[i][j]['F1 score']) + '\n')
			report_file.close()

			for row in lst:
				table.add_row(*row, style='bright_green')

			console = Console()
			console.print(table)
		#end
	#end
#end
