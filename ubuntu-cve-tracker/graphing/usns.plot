
set term png small size 640,480
set output "usns.png"

set xdata time
set timefmt "%Y-%m"
set format x "  %Y-%m"
set xtics out rotate

set key top left

set title "Published USNs"

plot "USN.data" using 1:2 with filledcurve x1 lc rgb 'purple' notitle, \
	"USN.data.truncated" using 1:2 with line lc rgb 'green' notitle smooth bezier
