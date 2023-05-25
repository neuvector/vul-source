" Vim syntax file
" Language: UCT CVEs
" Latest Revision: Jan 2023
"
" To use:
" $ mkdir -p ~/.vim/syntax
" $ ln -s $UCT/scripts/cve.vim ~/.vim/syntax/cve.vim
" Add to ~/.vimrc:
" autocmd BufNewFile,BufRead CVE-[0-9][0-9][0-9][0-9]-[0-9N]\\\{4,\} set syntax=cve
"
" TODO:
" - maybe do something with URLs
"

if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

let s:supported_releases = ["devel", "upstream", "product", "snap", "bionic", "focal", "jammy", "kinetic", "lunar", "mantic"]
let s:products = ["precise/esm", "trusty/esm", "esm-infra/xenial", "esm-apps/xenial", "esm-apps/bionic", "esm-apps/focal", "esm-apps/jammy", "fips", "fips-updates", "ros-esm"]
let s:eol_releases = ["warty", "hoary", "breezy", "dapper", "edgy", "feisty", "gutsy", "hardy", "intrepid", "jaunty", "karmic", "lucid", "maverick", "natty", "oneiric", "precise", "quantal", "raring", "saucy", "trusty", "utopic", "vivid", "vivid/stable-phone-overlay", "vivid/ubuntu-core", "wily", "xenial", "yakkety", "zesty", "artful", "cosmic", "disco", "eoan", "groovy", "hirsute", "impish"]
let s:all_releases = s:supported_releases + s:eol_releases + s:products

" Should match case except for the keys of each field
syn case match

" Everything that is not explicitly matched by the rules below
syn match cveElse "^.*$"

syn match cveSrcPkg contained "[a-z0-9][a-z0-9+.-]\+"
syn match cveId contained "CVE-[0-9][0-9][0-9][0-9]-[0-9N]\{4,}"
syn match cveDate contained  "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\( [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \([A-Z][A-Z][A-Z]\|[+-][01][0-9][0-9][0-9]\)\)\?"
syn match cveStatus contained "\(needs\-triage\|needed\|deferred\|pending\|released\|ignored\|not\-affected\|DNE\)"
syn match cveStatusExtra contained " (.\+)"

" Standard keys
syn match cveKey "^\%(Candidate\|PublicDate\|PublicDateAtUSN\|CRD\|References\|Description\|Ubuntu-Description\|Notes\|Mitigation\|CVSS\|Bugs\|Discovered-by\|Assigned-to\|Patches_[a-z0-9][a-z0-9+.-]\+\): *"

" Release/status key
" <release>_<srcpkg>: <status>
execute 'syn match cveKeyReleaseEOL "^\%(' . join(s:eol_releases, '\|') . '\)_[a-z0-9][a-z0-9+.-]\+: *"'
execute 'syn match cveKeyRelease "^\%(' . join(s:supported_releases, '\|') . '\)_[a-z0-9][a-z0-9+.-]\+: *"'

" Product/Release/status key
" <product>/<release>_<srcpkg>: <status>
execute 'syn match cveKeyProduct "^\%(' . join(s:products, '\|') . '\)_[a-z0-9][a-z0-9+.-]\+: *"'

" Priorities key
" Priority[_<srcpkg>[_<release>]]: <priority>
syn match cvePriorityValue contained "\(negligible\|low\|medium\|high\|critical\)"
execute 'syn match cvePriorityKey "^Priority\(_[a-z0-9][a-z0-9+.-]\+\(_\(' . join(s:all_releases, '\|') . '\)\)\?\)\?: *"'

" Tags key
" Tags_<srcpkg>[_<release>]: <tag>
syn match cveTagValue contained "\(apparmor\|fortify-source\|hardlink-restriction\|heap-protector\|not-ue\|pie\|stack-protector\|symlink-restriction\|universe-binary\) *"
execute 'syn match cveTagsKey "^Tags\(_[a-z0-9][a-z0-9+.-]\+\(_\(' . join(s:all_releases, '\|') . '\)\)\?\)\?: *"'

" Fields where we do strict syntax checking
syn region cveStrictField start="^Priority" end="$" contains=cvePriorityKey,cvePriorityValue oneline
syn region cveStrictField start="^Tags" end="$" contains=cveTagKey,cveTagValue oneline
syn region cveStrictField start="^Candidate" end="$" contains=cveKey,cveId
syn region cveStrictField start="^\(PublicDate\|CRD\)" end="$" contains=cveKey,cveDate
syn region cveStrictField start="^Patches_" end=":$" contains=cveKey,cveSrcPkg oneline
syn region cveStrictField start="^[a-z/-]\+_" end="$" contains=cveKeyRelease,cveKeyReleaseEOL,cveKeyProduct,cveStatus,cveStatusExtra oneline

if version >= 508 || !exists("did_cve_syn_inits")
  command -nargs=+ HiLink hi def link <args>

  HiLink cveKey                 Keyword
  HiLink cvePriorityKey         Keyword
  HiLink cveTagKey              Keyword
  HiLink cveKeyRelease          Keyword
  HiLink cveKeyReleaseEOL       Keyword
  HiLink cveKeyProduct          Type
  HiLink cveElse                Normal
  HiLink cveStrictField         Error
  HiLink cveStatus              Identifier
  HiLink cveStatusExtra         Number

  delcommand HiLink
endif

let b:current_syntax = "cve"
" vim: ts=8 sw=2
