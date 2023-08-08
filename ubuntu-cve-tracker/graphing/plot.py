#!/usr/bin/env python3
import sys, os
sys.path.append(os.path.expanduser("~/reviewed/scripts"))
import cve_lib

releases = ['warty','hoary','breezy'] + cve_lib.releases

print('''
set term png small size 800,480
set output "packages.png"

set key off
set xrange [-1:%d]
set offsets 0, 0, 100, 0
set boxwidth 0.2

set grid ytics
set ylabel "Packages in main/restricted (i386)"
''' % (len(releases)))

def dumpplot(suffix=''):
    plots = []
    index = -1
    for rel in releases:
        index += 1
        filename = "%s%s.data" % (rel, suffix)
        x, y = open(filename).readline().strip().split(' ')[1:3]
        print('set label "%d" center at %d,%d' % (int(y), int(x), int(y)+100))

        plots.append('"%s" using 2:3:xtic(1) title "%s" with boxes fs solid lc 1' % (filename, rel))

    print("plot " + ", ".join(plots))

dumpplot()

print('''
set output "sources.png"
set ylabel "Sources in main/restricted"
unset label
''')

dumpplot(suffix='-src')
