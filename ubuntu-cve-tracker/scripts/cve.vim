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
" - turn the release names into variables so we only have to update in one
"   place
" - maybe do something with URLs
"

if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

" Should match case except for the keys of each field
syn case match

" Everything that is not explicitly matched by the rules below
syn match cveElse "^.*$"

syn match cveRelease "\(devel\|upstream\|product\|snap\|warty\|hoary\|breezy\|dapper\|edgy\|feisty\|gutsy\|hardy\|intrepid\|jaunty\|karmic\|lucid\|maverick\|natty\|oneiric\|precise\|precise/esm\|quantal\|raring\|saucy\|trusty\|trusty/esm\|utopic\|vivid\|vivid/stable-phone-overlay\|vivid/ubuntu-core\|wily\|xenial\|yakkety\|zesty\|artful\|bionic\|cosmic\|disco\|eoan\|focal\|groovy\|hirsute\|impish\|jammy\|kinetic\|lunar\)"
syn match cveSrcPkg contained "[a-z0-9][a-z0-9+.-]\+"
syn match cveId contained "CVE-[0-9][0-9][0-9][0-9]-[0-9N]\{4,}"
syn match cveDate contained  "[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\( [0-2][0-9]:[0-5][0-9]:[0-5][0-9] \([A-Z][A-Z][A-Z]\|[+-][01][0-9][0-9][0-9]\)\)\?"
syn match cveStatus contained "\(needs\-triage\|needed\|deferred\|pending\|released\|ignored\|not\-affected\|DNE\)"
syn match cveStatusExtra contained " (.\+)"

" Standard keys
syn match cveKey "^\%(Candidate\|PublicDate\|PublicDateAtUSN\|CRD\|References\|Description\|Ubuntu-Description\|Notes\|Mitigation\|CVSS\|Bugs\|Discovered-by\|Assigned-to\|Patches_[a-z0-9][a-z0-9+.-]\+\): *"

" Release/status key
" <release>_<srcpkg>: <status>
syn match cveKeyRelease "^\%(devel\|upstream\|product\|snap\|warty\|hoary\|breezy\|dapper\|edgy\|feisty\|gutsy\|hardy\|intrepid\|jaunty\|karmic\|lucid\|maverick\|natty\|oneiric\|precise\|precise/esm\|quantal\|raring\|saucy\|trusty\|trusty/esm\|utopic\|vivid\|vivid/stable-phone-overlay\|vivid/ubuntu-core\|wily\|xenial\|yakkety\|zesty\|artful\|bionic\|cosmic\|disco\|eoan\|focal\|groovy\|hirsute\|impish\|jammy\|kinetic\|lunar\)_[a-z0-9][a-z0-9+.-]\+: *"

" Product/Release/status key
" <product>/<release>_<srcpkg>: <status>
syn match cveKeyProduct "^\(esm-apps/\)\?\%(devel\|upstream\|product\|snap\|warty\|hoary\|breezy\|dapper\|edgy\|feisty\|gutsy\|hardy\|intrepid\|jaunty\|karmic\|lucid\|maverick\|natty\|oneiric\|precise\|precise/esm\|quantal\|raring\|saucy\|trusty\|trusty/esm\|utopic\|vivid\|vivid/stable-phone-overlay\|vivid/ubuntu-core\|wily\|xenial\|yakkety\|zesty\|artful\|bionic\|cosmic\|disco\|eoan\|focal\|groovy\|hirsute\|impish\|jammy\|kinetic\|lunar\)_[a-z0-9][a-z0-9+.-]\+: *"


" Priorities key
" Priority[_<srcpkg>[_<release>]]: <priority>
syn match cvePriorityValue contained "\(negligible\|low\|medium\|high\|critical\)"
syn match cvePriorityKey "^Priority\(_[a-z0-9][a-z0-9+.-]\+\(_\(devel\|upstream\|product\|snap\|warty\|hoary\|breezy\|dapper\|edgy\|feisty\|gutsy\|hardy\|intrepid\|jaunty\|karmic\|lucid\|maverick\|natty\|oneiric\|precise\|precise/esm\|quantal\|raring\|saucy\|trusty\|trusty/esm\|utopic\|vivid\|vivid/stable-phone-overlay\|vivid/ubuntu-core\|wily\|xenial\|yakkety\|zesty\|artful\|bionic\|cosmic\|disco\|eoan\|focal\|groovy\|hirsute\|impish\|jammy\|kinetic\|lunar\)\)\?\)\?: *"

" Tags key
" Tags_<srcpkg>[_<release>]: <tag>
syn match cveTagValue contained "\(apparmor\|fortify-source\|hardlink-restriction\|heap-protector\|not-ue\|pie\|stack-protector\|symlink-restriction\|universe-binary\) *"
syn match cveTagKey "^Tags_[a-z0-9][a-z0-9+.-]\+\(_\(devel\|upstream\|product\|snap\|warty\|hoary\|breezy\|dapper\|edgy\|feisty\|gutsy\|hardy\|intrepid\|jaunty\|karmic\|lucid\|maverick\|natty\|oneiric\|precise\|precise/esm\|quantal\|raring\|saucy\|trusty\|trusty/esm\|utopic\|vivid\|vivid/stable-phone-overlay\|vivid/ubuntu-core\|wily\|xenial\|yakkety\|zesty\|artful\|bionic\|cosmic\|disco\|eoan\|focal\|groovy\|hirsute\|impish\|jammy\|kinetic\|lunar\)\)\?: *"

" Fields where we do strict syntax checking
syn region cveStrictField start="^Priority" end="$" contains=cvePriorityKey,cvePriorityValue oneline
syn region cveStrictField start="^Tags" end="$" contains=cveTagKey,cveTagValue oneline
syn region cveStrictField start="^Candidate" end="$" contains=cveKey,cveId
syn region cveStrictField start="^\(PublicDate\|CRD\)" end="$" contains=cveKey,cveDate
syn region cveStrictField start="^Patches_" end=":$" contains=cveKey,cveSrcPkg oneline
syn region cveStrictField start="^[a-z/-]\+_" end="$" contains=cveKeyRelease,cveStatus,cveStatusExtra oneline
syn region cveStrictField start="^[a-z/-]\+_" end="$" contains=cveKeyProduct,cveStatus,cveStatusExtra oneline

if version >= 508 || !exists("did_cve_syn_inits")
  command -nargs=+ HiLink hi def link <args>

  HiLink cveKey                 Keyword
  HiLink cvePriorityKey         Keyword
  HiLink cveTagKey              Keyword
  HiLink cveKeyRelease          Keyword
  HiLink cveKeyProduct          Keyword
  HiLink cveElse                Normal
  HiLink cveStrictField         Error

  delcommand HiLink
endif

let b:current_syntax = "cve"
" vim: ts=8 sw=2
