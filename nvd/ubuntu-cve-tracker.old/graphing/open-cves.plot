
set term png small size 640,480
set output "open-cves.png"

set xdata time
set timefmt "%Y-%m-%d"
set format x "  %Y-%m"
set key top left
set xtics out rotate

set title "Open CVEs (medium and higher priority)"

plot "CVE.data" using 1:($2+$3+$4) with filledcurve x1 lc rgb 'black' title 'Critical', \
     "CVE.data" using 1:($3+$4) with filledcurve x1 lc rgb 'red' title 'High', \
     "CVE.data" using 1:($4) with filledcurve x1 lc rgb 'orange' title 'Medium'
