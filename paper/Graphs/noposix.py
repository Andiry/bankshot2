#!/usr/bin/python
# -*- coding: utf-8 -*-

import numpy as np
import sys
import matplotlib.pyplot as plt
from matplotlib.ticker import ScalarFormatter

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
plt.rcParams['ytick.major.pad']='20'

fig = plt.figure()
ax = fig.add_subplot(111)
ax.set_yscale('log')
rects = [[] for i in range(3)]
color_pattern = ['g','blue', 'red', '0.3','0.6','0.9', '0.2', '0.5', '0.8', '0.1', '0.4','0.7', '1'] #light and contrasting colors
hatch_pattern = ['x','+','*','*','+','/', ' ', 'x', ' ', '-'] 
line_pattern = ['--',':','-','*','+','/', ' ', 'x', ' ', '-'] 
for j in range(3):
    name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
#    rects[j] = ax.bar(ind + width * (j + 1), data[j], width, color=color_pattern[j], hatch = hatch_pattern[j % len(hatch_pattern)])
    rects[j] = ax.plot(data[j], color=color_pattern[j], marker = hatch_pattern[j], markersize=20, linestyle=line_pattern[j])

# add some
ax.yaxis.labelpad = 40
ax.xaxis.labelpad = 15
ax.set_ylabel('Latency (nanosecond)', fontsize = '40')
ax.set_xlabel('Request size (bytes)', fontsize = '40')
#ax.set_xticks(ind + width * 2.5)
ax.set_xticklabels(traces)
#ax.set_ylim([1, 100000])
#ax.set_xlim([0, 9])
ax.axis([0, 8.2, 1, 150000])
#ax.yaxis.set_major_formatter(ScalarFormatter())
ax.set_yscale('log')
#ax.loglog()
plt.xticks(fontsize = '35')
plt.yticks(fontsize = '40')

ax.legend((rects[0][0], rects[1][0], rects[2][0]), types, loc = "upper left", prop = {'size': 30}, ncol = 1)
plt.show()
