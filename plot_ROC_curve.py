import pandas as pd, numpy as np, os
from sklearn.metrics import roc_curve, auc
import matplotlib.font_manager
import matplotlib.pyplot as plt
import random
from matplotlib.colors import ListedColormap, LinearSegmentedColormap
import matplotlib.cm
plt.rcParams.update({'font.size': 44})
plt.rcParams["font.family"] = "Times New Roman"
plt.rc('legend',fontsize=32)
#plt.rcParams["axes.labelweight"] = "bold"
#plt.style.use(['science','ieee'])
#plt.style.use(["science"])
plt.style.use('seaborn-dark-palette')

np.random.seed(19680801)

#results_dir = '/home/farhathz/riscv-malware-analysis/test_ROC_plotting'
results_dir = '/home/farhathz/test_ROC_plotting_whole'

values = []	
#boundaries = [0.23, 0.24, 0.25, 0.26, 0.27, 0.28, 0.29, 0.30]
#boundaries = [0.01, 0.02, 0.03, 0.04, 0.05]
subset_size = [8, 16, 32, 64, 128, 256, 329]

for file in sorted( os.listdir(results_dir) ):
	if not str(file).endswith('.csv'):
		continue

	print(file)
	data = pd.read_csv(os.path.join(results_dir, file))	

	n_classes = 2

	# Compute ROC curve and ROC area for each class
	fpr = dict()
	tpr = dict()
	roc_auc = dict()
	for i in range(n_classes):
		# isolate predictions for a specific class:
		class_i_labels = data['groundtruth']
		class_i_pred = data['prediction']

		# create list of scores for this class (in this case, 100% or 1):
		class_i_scores = pd.DataFrame( np.ones((len(class_i_labels), 1)))

		for S in range(len(class_i_scores)):
			if class_i_pred[S] == i:
				class_i_scores.loc[S] = 0.9
			else:
				class_i_scores.loc[S] = 0.1

		# calculate TPR and FPR for class i:
		fpr[i], tpr[i], _ = roc_curve(class_i_labels, class_i_scores, pos_label=i)
		
		# compute AUC based on TPR and FPR:
		roc_auc[i] = auc(fpr[i], tpr[i])

		if i == 1: # change to 0 for benign
			values.append([fpr[i], tpr[i], roc_auc[i]])

# create the plot:
plt.figure(figsize=(20, 8))
lw = 4

for D in range(len(values)):
	#plt.plot(fpr[i], tpr[i], color='darkorange', lw=lw, label='AUC (area = %0.2f)' % roc_auc[i])
	#plt.plot(values[D][0], values[D][1], lw=lw, label=str('Threshold = ' + str(boundaries[D]) + ' (AUC = %0.2f)' % values[D][2]) )
	plt.plot(values[D][0], values[D][1],  lw=lw, label=str('Subset size = ' + str(subset_size[D]) + ' (AUC = %0.2f)' % values[D][2]) )
plt.plot([0, 1], [0, 1], color='grey', lw=lw, linestyle='--')
#plt.xlim([0.0, 1.0])
#plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
#plt.title('ROC Curve: 6-Gram Matching for Varying Thresholds ' + ('(Malicious Class)' if i == 1 else '(Benign Class)'))
plt.legend(loc="lower right")
#plt.xticks(range(11))
#ax.get_yticklabels()[-3].set_weight("bold")
#ax.get_xticklabels()[5].set_weight("bold")
plt.show()	

