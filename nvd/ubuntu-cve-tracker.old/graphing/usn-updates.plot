
set term png small size 640,480
set output "usn-updates.png"

set xdata time
set timefmt "%Y-%m"
set format x "  %Y-%m"
set xtics out rotate
set key top right

set title "Monthly sum of each USN's Releases times CVEs"

plot "usn-updates.data" using 1:2 with filledcurve x1 lc rgb 'blue' title 'Releases * CVEs', \
	"usn-updates.data.truncated" using 1:2 with line lc rgb 'green' notitle smooth bezier
