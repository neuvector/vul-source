#!/usr/bin/env python2
releases = ['warty','hoary','breezy','dapper','edgy','feisty','gutsy','hardy','intrepid']

print '''
set term png small size 640,480
set output "packages.png"

set key off
set xrange [-1:%d]
set offsets 0, 0, 100, 0
set boxwidth 0.2

set grid ytics
set ylabel "Packages in main/restricted (i386)"
''' % (len(releases))


tics = []
plots = []
index = -1
for rel in releases:
    index += 1
    x, y = file("%s.data" % (rel)).readline().strip().split(' ')[1:3]
    print 'set label "%d" center at %d,%d' % (int(y), int(x), int(y)+100)

    plots.append('"%s.data" using 2:3:xtic(1) title "%s" with boxes fs solid lc 1' % (rel, rel))

print "plot " + ", ".join(plots)
