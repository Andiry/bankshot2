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
void = []
data1 = [[] for i in range(2)]
data4 = [[] for i in range(2)]
data16 = [[] for i in range(2)]

for line in f:
	line = line.rstrip()
	parts = line.split('\t')
	if round == 0:
		for j in range(2,len(parts)):
			types.append(parts[j])
	elif int(parts[1]) == 1:
		traces.append(parts[0])
		void.append("")
		for j in range(2,len(parts)):
			data1[j - 2].append(float(parts[j]) / 1000)
	elif int(parts[1]) == 4:
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
ax = fig.add_subplot(311)
rects = [[] for i in range(2)]
color_pattern = ['1','0', '0.7', '0.3','0.6','0.9', '0.2', '0.5', '0.8', '0.1', '0.4','0.7', '1'] #light and contrasting colors
hatch_pattern = ['\\','|','.','*','+','/', ' ', 'x', ' ', '-'] 
for j in range(2):
    name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
    rects[j] = ax.bar(ind + width * (j + 1), data1[j], width, color=color_pattern[j], hatch = hatch_pattern[j % len(hatch_pattern)])

# add some
#ax.yaxis.labelpad = 20
ax.set_ylabel('Bandwidth (GB/s)', fontsize = '15')
#ax.set_xlabel('Error Type', fontsize = '40')
#ax.set_xticks(ind + width*3)
ax.set_xticklabels(void, rotation = 45, ha = 'right')
ax.set_ylim([0, 38])
#ax.set_xlim([0, 6])
#plt.xticks(fontsize = '15')
plt.yticks(fontsize = '15')

ax.legend((rects[0][0], rects[1][0]), types, loc = "upper right", prop = {'size': 15}, ncol = 1)
#ax.set_title("1 thread", fontsize = '15')
ax.text(.5, .9, '1 thread', horizontalalignment = 'center', transform=ax.transAxes, fontsize = '15')

ax1 = fig.add_subplot(312)
rects = [[] for i in range(2)]
for j in range(2):
    name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
    rects[j] = ax1.bar(ind + width * (j + 1), data4[j], width, color=color_pattern[j], hatch = hatch_pattern[j % len(hatch_pattern)])

# add some
ax1.set_ylabel('Bandwidth (MB/s)', fontsize = '15')
#ax.set_xlabel('Error Type', fontsize = '40')
#ax1.set_xticks(ind + width*3)
ax1.set_xticklabels(void, rotation = 45, ha = 'right')
ax1.set_ylim([0, 38])
#ax1.set_xlim([0, 6])
#plt.xticks(fontsize = '15')
plt.yticks(fontsize = '15')

#ax1.legend((rects[0][0], rects[1][0]), types, loc = "upper right", prop = {'size': 40}, ncol = 1)
#ax1.set_title("4 threads", fontsize = '15')
ax1.text(.5, .9, '4 threads', horizontalalignment = 'center', transform=ax1.transAxes, fontsize = '15')

ax2 = fig.add_subplot(313)
rects = [[] for i in range(2)]
for j in range(2):
    name = 'rects' + str(j)
#    rects[j] = ax.bar(ind + width * j, data[j], width, color=color_pattern[j % len(color_pattern)], hatch = hatch_pattern[j % len(hatch_pattern)])
    rects[j] = ax2.bar(ind + width * (j + 1), data16[j], width, color=color_pattern[j], hatch = hatch_pattern[j % len(hatch_pattern)])

# add some
ax2.set_ylabel('Bandwidth (MB/s)', fontsize = '15')
#ax.set_xlabel('Error Type', fontsize = '40')
ax2.set_xticks(ind + width*3)
ax2.set_xticklabels(traces, rotation = 45, ha = 'right')
ax2.set_ylim([0, 38])
ax2.set_xlim([0, 6])
plt.xticks(fontsize = '15')
plt.yticks(fontsize = '15')

#ax2.legend((rects[0][0], rects[1][0]), types, loc = "upper right", prop = {'size': 40}, ncol = 1)
#ax2.set_title("16 threads", fontsize = '15')
ax2.text(.5, .9, '16 threads', horizontalalignment = 'center', transform=ax2.transAxes, fontsize = '15')

plt.show()
