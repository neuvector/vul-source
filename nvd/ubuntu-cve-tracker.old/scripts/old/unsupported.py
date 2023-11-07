#!/usr/bin/env python2
# Copyright (C) 2009 Canonical Ltd.
# Author: Kees Cook <kees@ubuntu.com>
#
# Reports unsupported packages in Dapper.  (requires package "python-apt")
#
# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import os, apt_pkg, sys, subprocess, optparse
apt_pkg.init_system();

supported = \
'''acct
acl
adduser
adns
aide
alien
alsa-driver
alsa-lib
alsa-utils
analog
ant
apache2
appconfig
apt
apt-listchanges
aptitude
at
attr
audiofile
authbind
autoconf
autoconf-nonfree
autofs
automake
automake1.9
autopkgtest
autotools-dev
avahi
awstats
backuppc
base-files
base-passwd
bash
bc
bcel
beecrypt
belocs-locales-bin
bind9
binutils
bison
bittornado
blt
bogofilter
bonnie++
bridge-utils
bsdmainutils
build-essential
busybox
bzip2
bzr
bzrtools
ca-certificates
casper
ccache
cdebconf
celementtree
checksecurity
chkrootkit
clientcookie
cloop
console-common
console-data
console-tools
coreutils
courier
cpio
cracklib2
cricket
cron
cup
cupsys
curl
cvs
cyrus-sasl2
dash
db3
db4.2
db4.3
dbus
debconf
debhelper
debian-goodies
debian-installer
debianutils
debootstrap
defoma
devmapper
devscripts
dh-make
dhcp3
dictd
dictionaries-common
diffstat
diffutils
discover1
discover1-data
dmapi
dmidecode
dnstracer
dosfstools
dovecot
dpkg
dput
dupload
e2fsprogs
ecj-bootstrap
ed
efibootmgr
egenix-mx-base
eject
elementtree
elilo
elinks
emacs-goodies-el
emacs21
emacsen-common
esound
ethtool
eunuchs
evms
exim4
expat
expect
exuberant-ctags
fakeroot
fdutils
fetchmail
file
findutils
flac
flex
fontconfig
foomatic-db
foomatic-db-engine
foomatic-db-hpijs
foomatic-filters
foomatic-filters-ppds
freecdb
freetds
freetype
fribidi
fuse
gadfly
gamin
gcc-3.3
gcc-3.4
gcc-4.0
gcc-defaults
gcj-4.1
gdb
gdbm
geoip
germinate
gettext
git-core
gle
glib1.2
glib2.0
glibc
gmp
gnupg
gnupginterface
gnutls12
gpm
graphviz
grep
grep-dctrl
grepmap
groff
grub
gs-common
gs-esp
gsfonts
gsl
gutenprint
gzip
hdparm
heartbeat
heimdal
hello
hello-debhelper
hfsplus
hostname
hplip
html2text
htmlgen
hwdata
ifenslave-2.6
ifupdown
ijs
indent
initramfs-tools
inputattach
intltool-debian
iproute
ipsec-tools
iptables
iptraf
iputils
ipvsadm
irssi
isdnutils
jade
java-common
java-gcj-compat
jfsutils
jlex
john
keepalived
kernel-package
klibc
krb5
langpack-locales
language-pack-af
language-pack-af-base
language-pack-am
language-pack-am-base
language-pack-an
language-pack-an-base
language-pack-ar
language-pack-ar-base
language-pack-as
language-pack-as-base
language-pack-az
language-pack-az-base
language-pack-be
language-pack-be-base
language-pack-bg
language-pack-bg-base
language-pack-bn
language-pack-bn-base
language-pack-br
language-pack-br-base
language-pack-bs
language-pack-bs-base
language-pack-ca
language-pack-ca-base
language-pack-co
language-pack-co-base
language-pack-cs
language-pack-cs-base
language-pack-cy
language-pack-cy-base
language-pack-da
language-pack-da-base
language-pack-de
language-pack-de-base
language-pack-el
language-pack-el-base
language-pack-en
language-pack-en-base
language-pack-eo
language-pack-eo-base
language-pack-es
language-pack-es-base
language-pack-et
language-pack-et-base
language-pack-eu
language-pack-eu-base
language-pack-fa
language-pack-fa-base
language-pack-fi
language-pack-fi-base
language-pack-fo
language-pack-fo-base
language-pack-fr
language-pack-fr-base
language-pack-ga
language-pack-ga-base
language-pack-gl
language-pack-gl-base
language-pack-gu
language-pack-gu-base
language-pack-he
language-pack-he-base
language-pack-hi
language-pack-hi-base
language-pack-hr
language-pack-hr-base
language-pack-hu
language-pack-hu-base
language-pack-hy
language-pack-hy-base
language-pack-ia
language-pack-ia-base
language-pack-id
language-pack-id-base
language-pack-is
language-pack-is-base
language-pack-it
language-pack-it-base
language-pack-ja
language-pack-ja-base
language-pack-ka
language-pack-ka-base
language-pack-kk
language-pack-kk-base
language-pack-kn
language-pack-kn-base
language-pack-ko
language-pack-ko-base
language-pack-ku
language-pack-ku-base
language-pack-ky
language-pack-ky-base
language-pack-la
language-pack-la-base
language-pack-lb
language-pack-lb-base
language-pack-lg
language-pack-lg-base
language-pack-li
language-pack-li-base
language-pack-lo
language-pack-lo-base
language-pack-lt
language-pack-lt-base
language-pack-lv
language-pack-lv-base
language-pack-mg
language-pack-mg-base
language-pack-mi
language-pack-mi-base
language-pack-mk
language-pack-mk-base
language-pack-ml
language-pack-ml-base
language-pack-mn
language-pack-mn-base
language-pack-mr
language-pack-mr-base
language-pack-ms
language-pack-ms-base
language-pack-my
language-pack-my-base
language-pack-nb
language-pack-nb-base
language-pack-ne
language-pack-ne-base
language-pack-nl
language-pack-nl-base
language-pack-nn
language-pack-nn-base
language-pack-no
language-pack-no-base
language-pack-oc
language-pack-oc-base
language-pack-or
language-pack-or-base
language-pack-pa
language-pack-pa-base
language-pack-pl
language-pack-pl-base
language-pack-pt
language-pack-pt-base
language-pack-rm
language-pack-rm-base
language-pack-ro
language-pack-ro-base
language-pack-ru
language-pack-ru-base
language-pack-rw
language-pack-rw-base
language-pack-se
language-pack-se-base
language-pack-si
language-pack-si-base
language-pack-sk
language-pack-sk-base
language-pack-sl
language-pack-sl-base
language-pack-sq
language-pack-sq-base
language-pack-sr
language-pack-sr-base
language-pack-sv
language-pack-sv-base
language-pack-sw
language-pack-sw-base
language-pack-ta
language-pack-ta-base
language-pack-te
language-pack-te-base
language-pack-tg
language-pack-tg-base
language-pack-th
language-pack-th-base
language-pack-tk
language-pack-tk-base
language-pack-tl
language-pack-tl-base
language-pack-tr
language-pack-tr-base
language-pack-ug
language-pack-ug-base
language-pack-uk
language-pack-uk-base
language-pack-ur
language-pack-ur-base
language-pack-uz
language-pack-uz-base
language-pack-vi
language-pack-vi-base
language-pack-wa
language-pack-wa-base
language-pack-wo
language-pack-wo-base
language-pack-xh
language-pack-xh-base
language-pack-yi
language-pack-yi-base
language-pack-yo
language-pack-yo-base
language-pack-zh
language-pack-zh-base
language-pack-zu
language-pack-zu-base
lapack3
laptop-detect
latex-ucs
less
lftp
libaal
libaio
libapache-mod-auth-mysql
libapache-mod-security
libapache2-mod-auth-pam
libapache2-mod-auth-pgsql
libapache2-mod-auth-plain
libapache2-mod-macro
libapache2-mod-perl2
libapache2-mod-python
libarchive-zip-perl
libart-lgpl
libcap
libchart-perl
libclass-accessor-perl
libcompress-zlib-perl
libconfig-inifiles-perl
libconvert-asn1-perl
libcrypt-blowfish-perl
libdaemon
libdate-manip-perl
libdbd-mysql-perl
libdbi-perl
libdebian-installer
libdevel-symdump-perl
libdigest-hmac-perl
libdigest-sha1-perl
libdrm
libedit
libelf
libemail-valid-perl
libevent
libfile-rsyncp-perl
libgc
libgcrypt11
libgd-gd2-perl
libgd-graph-perl
libgd-text-perl
libgd2
libgnucrypto-java
libgpg-error
libhnj
libhtml-parser-perl
libhtml-tagset-perl
libhtml-tree-perl
libice
libidn
libio-string-perl
libiodbc2
libjaxp1.2-java
libjessie-java
libjpeg6b
liblocale-gettext-perl
liblockfile
libmail-sendmail-perl
libmailtools-perl
libnet-daemon-perl
libnet-dns-perl
libnet-domain-tld-perl
libnet-ip-perl
libnet-ldap-perl
libnfsidmap
libnss-db
libogg
libpam-foreground
libpam-opie
libpaper
libparse-debianchangelog-perl
libpcap0.8
libplrpc-perl
libpng
libregexp-java
libselinux
libsepol
libsigc++-2.0
libsm
libsnmp-session-perl
libtasn1-2
libtemplate-perl
libtext-charwidth-perl
libtext-iconv-perl
libtext-wrapi18n-perl
libtextwrap
libtool
libungif4
liburi-perl
libusb
libwww-perl
libx11
libxalan2-java
libxau
libxaw
libxerces2-java
libxext
libxml2
libxmu
libxp
libxpm
libxslt
libxt
libxxf86vm
lilo
linda
lintian
linux-atm
linux-backports-modules-2.6.15
linux-kernel-headers
linux-meta
linux-ntfs
linux-restricted-modules-2.6.15
linux-source-2.6.15
linux32
lm-sensors
lockfile-progs
logcheck
logrotate
lpr
lprng
lsb
lshw
lsof
ltrace
ltsp
ltsp-utils
lua50
lvm-common
lvm2
lzo
m4
mailman
mailx
make
makedev
man-db
manpages
mawk
mdadm
mdbtools
memtest86+
mesa
mhash
mii-diag
mime-support
minicom
miscfiles
module-init-tools
moin
mtr
multipath-tools
mutt
mysql-dfsg-5.0
nagios
nagios-plugins
nano
nbd
ncurses
neon
net-snmp
net-tools
netbase
netcat
netcdf
netkit-base
netkit-ftp
netkit-telnet
netpbm-free
nevow
newt
nfs-utils
nis
nmap
ntp
nvidia-kernel-common
ocaml
ocfs2-tools
opencdk8
openjade
openldap2
openldap2.2
openslp
openssh
openssh-blacklist
openssl
opie
palo
pam
paramiko
parted
patch
patchutils
pax
pbuilder
pciutils
pcmciautils
pcre3
perl
pgtcl
php5
pkg-config
pkgstriptranslations
pnm2ppa
po-debconf
poppler
popt
popularity-contest
portmap
postfix
postgresql-8.1
postgresql-common
ppp
pppconfig
pppoeconf
pptpd
procmail
procps
progsreiserfs
psmisc
psycopg
pwgen
pychecker
pycurl
pygobject
pygresql
pymacs
pyopenssl
python-adns
python-apt
python-clientform
python-crypto
python-defaults
python-docutils
python-gd
python-geoip
python-htmltmpl
python-imaging
python-ldap
python-mechanize
python-mode
python-mysqldb
python-numarray
python-numeric
python-pam
python-pgsql
python-pqueue
python-pullparser
python-pylibacl
python-pysqlite2
python-pyxattr
python-reportlab
python-scientific
python-soappy
python-sqlite
python-stats
python-tz
python-xml
python2.4
quagga
quota
radvd
raptor
rasqal
rcs
readahead-list
readline5
recode
redhat-cluster-suite
redland
redland-bindings
refblas3
reiser4progs
reiserfsprogs
reportbug
rpm
rrdtool
rsync
ruby1.8
samba
screen
sed
setserial
shadow
shorewall
shtool
siege
simpletal
slang2
slocate
smartmontools
sqlite
sqlite3
squid
ssl-cert
stlport4.6
strace
subversion
sudo
syck
sysfsutils
sysklogd
syslinux
sysvinit
t1lib
tar
tcl8.4
tcp-wrappers
tcpdump
tetex-base
tetex-bin
tex-common
texinfo
tftp-hpa
tiff
time
timedate
tk8.4
traceroute
ttf-bitstream-vera
ttf-dejavu
ttf-freefont
twisted
twisted-conch
twisted-lore
twisted-mail
twisted-names
twisted-news
twisted-runner
twisted-web
twisted-web2
twisted-words
ubuntu-keyring
ubuntu-meta
ucf
udev
unixodbc
unzip
usbutils
user-setup
utf8-migration-tool
util-linux
uucp
valgrind
vim
vlan
vnc
vsftpd
w3m
wdiff
wget
whois
wireless-tools
wpasupplicant
xaw3d
xfsdump
xfsprogs
xinetd
zip
zlib
zope-common
zope3
zsh'''.split('\n')


def _find_sources_from_apt():
  collection = []

  saw = dict()
  lists = '/var/lib/apt/lists'
  count = 0
  for f in os.listdir(lists):
    if not f.endswith('_source_Sources') and not '-commercial_main_binary-' in f:
        continue
    count += 1
    parts = f.split('_')
    parts.pop() # _Sources
    parts.pop() # _source
    section = parts.pop() # _main
    release_real = parts.pop() # _dapper
    saw.setdefault(release_real,True)
    tmp = release_real.split('-')
    release = tmp[0]
    if len(tmp) > 1:
    	pocket = tmp[1]
    else:
        pocket = ''
    collection += [(os.path.join(lists,f), release, pocket, section)]

  if count == 0:
    print >>sys.stderr, "deb-src lines are required in /etc/apt/sources.list"
    sys.exit(1)
  return collection

def load_collection(item, source_map):
        tagfile, release, pocket, section = item

        tags = None
        if tagfile.endswith('.gz'):
            tags = subprocess.Popen(['/bin/gunzip','-c',tagfile], stdout=subprocess.PIPE).stdout
        else:
            tags = file(tagfile)
        parser = apt_pkg.TagFile(tags)
        while parser.step():
            pkg = parser.section['Package']
            source_map.setdefault(release,dict()).setdefault(pkg, {'section': 'unset', 'version': '0', 'pocket': 'unset' })
            source_map[release][pkg]['section'] = section
            if apt_pkg.version_compare(parser.section['Version'],source_map[release][pkg]['version'])>0:
                source_map[release][pkg]['pocket'] = pocket
                source_map[release][pkg]['version'] = parser.section['Version']
                source_map[release][pkg]['binaries'] = parser.section['Binary'].split(', ')

        return source_map

# release -> pkg -> dict( 'section', 'pocket', 'version' )
def load():
    source_map = dict()
    for item in _find_sources_from_apt():
        load_collection(item, source_map)
    return source_map


parser = optparse.OptionParser('%prog [OPTIONS] [binpkg ...]')
parser.add_option("-v", "--verbose", help="Show verbose output", action='store_true')
parser.add_option("--main", help="Only include main/restricted packages in unsupported list", action='store_true')
(opt, args) = parser.parse_args()

try:
    srcs = load()['dapper']
except:
    print >>sys.stderr, "This script only works on Dapper."
    sys.exit(1)

bins = []
bin_srcs = dict()
if len(args)==0:
    for pair in args:
        bin, src = pair.split(':')
        bins.append(bin)
        bin_srcs[bin] = src

if len(bins) == 0:
    parser = apt_pkg.TagFile(file('/var/lib/dpkg/status'))
    while parser.step():
        if 'installed' in parser.section['Status']:
            bin = parser.section['Package']
            try:
                src = parser.section['Source'].split()[0]
            except:
                # Find first-match
                src = None
                for test_src in srcs:
                    if bin in srcs[test_src]['binaries']:
                        src = test_src
                        break
                if src == None:
                    print >>sys.stderr, '"Source" missing for %s' % (bin)
                    sys.exit(1)
            bins.append(bin)
            bin_srcs[bin] = src

unsupported = 0
for bin in sorted(bins):
    src = bin_srcs[bin]
    if src not in supported:
        unsupported += 1
        if not opt.main or srcs[src]['section'] in ['main','restricted']:
            print '%s (src: %s)' % (bin, src)
if opt.verbose:
    print >>sys.stderr, 'Examined %d binary packages (%d unsupported)' % (len(bins), unsupported)
