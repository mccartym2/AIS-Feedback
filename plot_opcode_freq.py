import pandas as pd, numpy as np, os
from sklearn.metrics import roc_curve, auc
from pylab import *
import matplotlib.font_manager
import matplotlib.pyplot as plt
#plt.rcParams["font.weight"] = "bold"
#plt.rcParams["axes.labelweight"] = "bold"
#plt.style.use(["science","ieee"])
#plt.style.use(["science"])
#plt.style.use('seaborn-dark-palette')
plt.rcParams["font.family"] = "Times New Roman"
plt.rcParams.update({'font.size': 44})

#, "font.weight" : "bold", "axes.labelweight" : "bold"
#plt.rcParams.update({'font.size': 4})
#rc('axes', linewidth=2)

data = pd.read_csv('/home/farhathz/frequency_string_matches-method=NSA-ngram=6.csv')	
opcode_ids = [x for x in range(len(data))]

# create the plot:
plt.figure(figsize=(12, 5))
#ax = fig.add_axes([0,0,1,1])
plt.bar(opcode_ids, data['hit_count'], color = 'dimgrey')
#plt.plot(opcode_ids, data['hit_count'], '-', lw = '6')
#plt.plot([0, 1], [0, 1], color='grey', linestyle='--')
#plt.xlim([0.0, 1.0])
#plt.ylim([0.0, 1.05])
plt.xlabel('Antibody ID')
plt.ylabel('Opcode Sequence Freq')
#plt.title('ROC Curve: 14-Gram Matching for Varying Thresholds ' + ('(Malicious Class)' if i == 1 else '(Benign Class)'))
#plt.legend(loc="lower right")
#plt.xticks(range(11))
#ax.get_yticklabels()[-3].set_weight("bold")
#ax.get_xticklabels()[5].set_weight("bold")
plt.savefig('opcode_fig.pdf') 
plt.show()
 

