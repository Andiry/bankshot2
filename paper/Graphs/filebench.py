#!/usr/bin/python
# -*- coding: utf-8 -*-

import numpy as np
import sys
import matplotlib.pyplot as plt

if len(sys.argv) < 2:
	print "Parameter Error"
	exit(0)

filename = sys.argv[1]
f = open(filename, 'r')

round = 0
workloads = [[] for i in range(3)]
traces = []
data128=[]
data512=[]
data2048=[]
types=[]
i = 0

for line in f:
	line = line.rstrip()
	parts = line.split('\t')
	if round == 0:
		i == 1
	elif parts[1] == '128k':
		data128.append(float(parts[3]) / float(parts[2]))
	elif parts[1] == '512k':
		data512.append(float(parts[3]) / float(parts[2]))
	elif parts[1] == '2m':
		data2048.append(float(parts[3]) / float(parts[2]))
	if round % 3 == 1:
		types.append(parts[1])
	if round > 0 and round < 4:
		traces.append(parts[0])
	round += 1

file.close(f)
print traces
print data128
print data512
print data2048



N = len(data128)
ind = np.arange(N)
width = 0.2

print ind

plt.rcParams['xtick.major.pad']='10'
plt.rcParams['ytick.major.pad']='20'

fig = plt.figure()
ax = fig.add_subplot(111)
rects = [[] for i in range(3)]
color_pattern = ['1','0.6', '0.2', '0.3','0.6','0.9', '0.2', '0.5', '0.8', '0.1', '0.4','0.7', '1'] #light and contrasting colors
hatch_pattern = ['\\','/',' ','*','+','/', ' ', 'x', ' ', '-'] 

rects[0] = ax.bar(ind + width * (0 + 1), data128, width, color=color_pattern[0], hatch = hatch_pattern[0 % len(hatch_pattern)])
rects[1] = ax.bar(ind + width * (1 + 1), data512, width, color=color_pattern[1], hatch = hatch_pattern[1 % len(hatch_pattern)])
rects[2] = ax.bar(ind + width * (2 + 1), data2048, width, color=color_pattern[2], hatch = hatch_pattern[2 % len(hatch_pattern)])
ax.plot((0,3),(1,1),'k-')

# add some
ax.yaxis.labelpad = 30
ax.set_ylabel('Normalized Ops per second', fontsize = '40')
#ax.set_xlabel('Error Type', fontsize = '40')
ax.set_xticks(ind + width*2.5)
ax.set_xticklabels(traces)
ax.set_ylim([0, 4])
ax.set_xlim([0, 3])
plt.xticks(fontsize = '35')
plt.yticks(fontsize = '40')

ax.legend((rects[0][0], rects[1][0], rects[2][0]), types, loc = "upper left", prop = {'size': 40}, ncol = 2)
plt.show()
