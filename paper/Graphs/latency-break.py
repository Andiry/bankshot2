#!/usr/bin/python
# -*- coding: utf-8 -*-

import numpy as np
import sys
import matplotlib.pyplot as plt
from operator import add

if len(sys.argv) < 2:
	print "Parameter Error"
	exit(0)

filename = sys.argv[1]
f = open(filename, 'r')

round = 0
types = []
traces = []
data=[[] for i in range(3)]

for line in f:
	line = line.rstrip()
	parts = line.split('\t')
	if round == 0:
		for j in range(1,len(parts)):
			types.append(parts[j])
	else:
		traces.append(parts[0])
		for j in range(1,len(parts)):
			data[j - 1].append(float(parts[j]))
	round += 1

file.close(f)
print types
print traces
print data[0]
print data[1]
print data[2]

N = len(traces)
ind = np.arange(N)
width = 0.2

print ind
print len(data[0])

plt.rcParams['xtick.major.pad']='30'
plt.rcParams['ytick.major.pad']='20'

fig = plt.figure()
ax = fig.add_subplot(111)
rects = [[] for i in range(3)]
color_pattern = ['0.9','0','0.4','c','0', '#eeefff', '0.6', '0.3','0.6','0.9', '0.2', '0.5', '0.8', '0.1', '0.4','0.7', '1'] #light and contrasting colors
hatch_pattern = ['','','','\\','|','/','*','+','/', ' ', 'x', ' ', '-'] 

name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
rects[0] = ax.bar(ind + width * 2, data[0], width, color=color_pattern[0], hatch = hatch_pattern[0 % len(hatch_pattern)])
rects[1] = ax.bar(ind + width * 2, data[1], width, color=color_pattern[1], hatch = hatch_pattern[1 % len(hatch_pattern)], bottom=data[0])
rects[2] = ax.bar(ind + width * 2, data[2], width, color=color_pattern[2], hatch = hatch_pattern[2 % len(hatch_pattern)], bottom=map(add, data[0], data[1]))

# add some
ax.set_ylabel('Latency (Nanosecond)', fontsize = '35')
ax.yaxis.labelpad = 30
#ax.set_xlabel('Error Type', fontsize = '40')
ax.set_xticks(ind + width * 2.5)
ax.set_xticklabels(traces)
ax.set_ylim([0, 700])
ax.set_xlim([0, 2])
plt.xticks(fontsize = '35')
plt.yticks(fontsize = '35')

ax.legend((rects[0][0], rects[1][0], rects[2][0]), types, loc = "upper left", prop = {'size': 35}, ncol = 1)
plt.show()
