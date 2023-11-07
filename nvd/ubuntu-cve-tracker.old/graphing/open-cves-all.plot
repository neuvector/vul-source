
set term png small size 640,480
set output "open-cves-all.png"

set xdata time
set timefmt "%Y-%m-%d"
set format x "  %Y-%m"
set key top left
set xtics out rotate

set title "Open CVEs"

plot "CVE.data" using 1:($2+$3+$4+$5) with filledcurve x1 lc rgb 'black' title 'Critical', \
     "CVE.data" using 1:($3+$4+$5) with filledcurve x1 lc rgb 'red' title 'High', \
     "CVE.data" using 1:($4+$5) with filledcurve x1 lc rgb 'orange' title 'Medium', \
     "CVE.data" using 1:($5) with filledcurve x1 lc rgb 'yellow' title 'Low' 
