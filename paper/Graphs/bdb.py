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
types = []
traces = []
data=[[] for i in range(2)]

for line in f:
	line = line.rstrip()
	parts = line.split('\t')
	if round == 0:
		for j in range(2,len(parts)):
			types.append(parts[j])
	else:
		traces.append(parts[0])
		for j in range(2,len(parts)):
			data[j - 2].append(float(parts[j]))
	round += 1

file.close(f)
print types
print traces
print data[0]

N = len(traces)
ind = np.arange(N)
width = 0.2

print ind
print len(data[0])

plt.rcParams['xtick.major.pad']='10'
plt.rcParams['ytick.major.pad']='10'

fig = plt.figure()
ax = fig.add_subplot(111)
rects = [[] for i in range(2)]
color_pattern = ['1','0', '0.7', '0.3','0.6','0.9', '0.2', '0.5', '0.8', '0.1', '0.4','0.7', '1'] #light and contrasting colors
hatch_pattern = ['\\','/','.','*','+','/', ' ', 'x', ' ', '-'] 
for j in range(2):
    name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
    rects[j] = ax.bar(ind + width * (j + 1), data[j], width, color=color_pattern[j], hatch = hatch_pattern[j % len(hatch_pattern)])

# add some
ax.yaxis.labelpad = 10
ax.set_ylabel('Ops per second', fontsize = '15')
#ax.set_xlabel('Error Type', fontsize = '40')
ax.set_xticks(ind + width*2)
ax.set_xticklabels(traces)
ax.set_ylim([0, 45000])
ax.set_xlim([0, 4])
plt.xticks(fontsize = '15')
plt.yticks(fontsize = '15')
ax.xaxis.labelpad = 10
ax.set_xlabel('Threads', fontsize = '15')

ax.legend((rects[0][0], rects[1][0]), types, loc = "upper left", prop = {'size': 15}, ncol = 1)
plt.show()
