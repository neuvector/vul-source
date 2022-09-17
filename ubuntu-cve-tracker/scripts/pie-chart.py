#!/usr/bin/env python2
from pychart import *
import sys

theme.use_color = True
theme.default_font_size = 14
theme.reinitialize()

png = canvas.init(fname=sys.argv[1], format="png")

input = []
arcs = []
total = 0
for line in sys.stdin:
    name, value = line.strip().split(' ',1)
    value = int(value)
    total += value
    input.append((name, value))
data = []
for item in input:
    name, value = item
    data.append(("%s (%d: %.1f%%)" % (name,value, value*100.0/total), value))
    arcs.append(0)
data.reverse()

ar = area.T(size=(700,600), legend=legend.T(),
            x_grid_style = None, y_grid_style = None)

plot = pie_plot.T(data=data, arc_offsets=arcs,
                  shadow = (2, -2, fill_style.gray50),
                  label_offset = 50, start_angle = 180,
                  arrow_style = arrow.a3)
ar.add_plot(plot)
ar.draw(png)

tb = text_box.T(loc=(0,600), text="/vT/hC/20"+" ".join(sys.argv[2:]), line_style=None)
tb.draw(png)
