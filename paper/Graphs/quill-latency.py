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
data1 = [[] for i in range(2)]
data4 = [[] for i in range(2)]
data16 = [[] for i in range(2)]

for line in f:
	line = line.rstrip()
	parts = line.split('\t')
	if round == 0:
		for j in range(2,len(parts)):
			types.append(parts[j])
	elif int(parts[1]) == 0:
		traces.append(parts[0])
		for j in range(2,len(parts)):
			data1[j - 2].append(float(parts[j]) / 1000)
	elif int(parts[1]) == 1:
		for j in range(2,len(parts)):
			data4[j - 2].append(float(parts[j]) / 1000)
	elif int(parts[1]) == 16:
		for j in range(2,len(parts)):
			data16[j - 2].append(float(parts[j]) / 1000)
	round += 1

file.close(f)
print types
print traces
print data1[0]
print data4[0]
print data16[0]

N = len(traces)
ind = np.arange(N)
width = 0.2

print ind
print len(data1[0])

plt.rcParams['xtick.major.pad']='10'
plt.rcParams['ytick.major.pad']='10'

fig = plt.figure()
ax = fig.add_subplot(211)
rects = [[] for i in range(2)]
color_pattern = ['1','0', '0.7', '0.3','0.6','0.9', '0.2', '0.5', '0.8', '0.1', '0.4','0.7', '1'] #light and contrasting colors
hatch_pattern = ['\\','|','.','*','+','/', ' ', 'x', ' ', '-'] 
for j in range(2):
    name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
    rects[j] = ax.bar(ind + width * (j + 1), data1[j], width, color=color_pattern[j], hatch = hatch_pattern[j % len(hatch_pattern)])

# add some
ax.yaxis.labelpad = 10
ax.set_ylabel('Latency (microsecond)', fontsize = '20')
#ax.set_xlabel('Error Type', fontsize = '40')
ax.set_xticks(ind + width*2)
ax.set_xticklabels(traces)
ax.set_ylim([0, 2])
ax.set_xlim([0, 6])
plt.xticks(fontsize = '20')
plt.yticks(fontsize = '20')

ax.legend((rects[0][0], rects[1][0]), types, loc = "center left", prop = {'size': 20}, ncol = 1)
#ax.set_title("Read", fontsize = '20')
ax.text(.5, .9, 'Read', horizontalalignment = 'center', transform=ax.transAxes, fontsize = '20')

ax1 = fig.add_subplot(212)
rects = [[] for i in range(2)]
for j in range(2):
    name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
    rects[j] = ax1.bar(ind + width * (j + 1), data4[j], width, color=color_pattern[j], hatch = hatch_pattern[j % len(hatch_pattern)])

# add some
#ax1.set_ylabel('Bandwidth (MB/s)', fontsize = '40')
#ax.set_xlabel('Error Type', fontsize = '40')
ax1.set_xticks(ind + width*2)
ax1.set_xticklabels(traces)
ax1.yaxis.labelpad = 10
ax1.set_ylabel('Latency (microsecond)', fontsize = '20')
ax1.set_ylim([0, 2])
ax1.set_xlim([0, 6])
ax1.xaxis.labelpad = 10
ax1.set_xlabel('Request size (bytes)', fontsize = '20')
plt.xticks(fontsize = '20')
plt.yticks(fontsize = '20')

#ax1.legend((rects[0][0], rects[1][0]), types, loc = "upper right", prop = {'size': 40}, ncol = 1)
#ax1.set_title("Write", fontsize = '20')
ax1.text(.5, .9, 'Write', horizontalalignment = 'center', transform=ax1.transAxes, fontsize = '20')

plt.show()
