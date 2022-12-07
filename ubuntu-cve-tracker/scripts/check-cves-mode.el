;;; check-cves-mode.el --- Major mode for working with the output of check-cves         -*- lexical-binding: t; -*-

;; Copyright (c) 2018 Alex Murray

;; Author: Alex Murray <alex.murray@canonical.com>
;; Maintainer: Alex Murray <alex.murray@canonical.com>
;; URL: https://launchpad.net/ubuntu-cve-tracker
;; Version: 0.1
;; Package-Requires: ((emacs "26.1"))

;; This file is not part of GNU Emacs.

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <http://www.gnu.org/licenses/>.

;;; Commentary:

;;;; Setup

;; (require 'check-cves-mode)

;;; Code:
(require 'cl-lib)
(require 'eldoc)
(require 'bug-reference)
(require 'hl-line)
(require 'seq)

;;; Forward declaration of optional dependencies
(declare-function company-doc-buffer "ext:company.el")

(defvar check-cves-mode-actions '(("add" . "Create a new active CVE entry.")
                                  ("edit" . "Create a new active CVE entry and open for editing later.")
                                  ("unembargo" . "Unembargo a CVE that is now public.")
                                  ("ignore" . "Ignore this CVE and add it to ignored/not-for-us.txt.")
                                  ("skip" . "Skip processing of this CVE for now.")))

(defvar check-cves-mode-priorities '(("negligible" . "Something that is technically a security problem, but is only theoretical in nature, requires a very special situation, has almost no install base, or does no real damage.  These tend not to get backport from upstreams,and will likely not be included in security updates unless there is an easy fix and some other issue causes an update.")
                                     ("low" . "Something that is a security problem, but is hard to exploit due to environment, requires a user-assisted attack, a small install base, or does very little damage. These tend to be included in security updates only when higher priority issues require an update, or if many low priority issues have built up.")
                                     ("medium" . "Something is a real security problem, and is exploitable for many people.  Includes network daemon denial of service attacks, cross-site scripting, and gaining user privileges. Updates should be made soon for this priority of issue.")
                                     ("high" . "A real problem, exploitable for many people in a default installation.  Includes serious remote denial of services,local root privilege escalations, or data loss.")
                                     ("critical" . "A world-burning problem, exploitable for nearly all people in a default installation of Ubuntu.  Includes remote root privilege escalations, or massive data loss.")))

(defvar check-cves-mode-invalid-actions'("skip"))

(defvar check-cves-mode-invalid-priorities '("untriaged"))

(defvar check-cves-mode-cve-id-regexp "^\\(CVE-[[:digit:]]\\{4\\}-[[:digit:]]\\{4,\\}\\)")

(defvar check-cves-mode-font-lock-defaults
  `(((,(regexp-opt check-cves-mode-invalid-actions 'words) . font-lock-warning-face)
     (,(regexp-opt check-cves-mode-invalid-priorities 'words) . font-lock-warning-face)
     (,(regexp-opt (mapcar #'car check-cves-mode-actions) 'words) . font-lock-keyword-face)
     (,(regexp-opt (mapcar #'car check-cves-mode-priorities) 'words) . font-lock-type-face)
     ;; CVE Ids
     (,check-cves-mode-cve-id-regexp 1 font-lock-variable-name-face t))))

(defvar check-cves-mode-syntax-table
  (let ((table (make-syntax-table)))
    ;; # is comment start
    (modify-syntax-entry ?# "<" table)
    ;; newline finishes comment line
    (modify-syntax-entry ?\n ">" table)
    table))

;;;###autoload
(defun check-cves-mode-next (arg)
  "Jump to the next CVE.
The prefix argument ARG specifies how many CVEs to move.
A negative argument means move backward that many keywords."
  (interactive "p")
  (if (< arg 0)
      (check-cves-mode-previous (- arg))
    (while (and (> arg 0)
                (not (eobp))
                (let ((case-fold-search nil))
                  (when (looking-at check-cves-mode-cve-id-regexp)
                    (goto-char (match-end 0)))
                  (or (re-search-forward check-cves-mode-cve-id-regexp nil t)
                      (user-error "No more matches"))))
      (goto-char (match-beginning 0))
      (cl-decf arg))))

;;;###autoload
(defun check-cves-mode-previous (arg)
  "Jump to the previous CVE.
The prefix argument ARG specifies how many keywords to move.
A negative argument means move forward that many keywords."
  (interactive "p")
  (if (< arg 0)
      (check-cves-mode-next (- arg))
    (while (and (> arg 0)
                (not (bobp))
                (let ((case-fold-search nil)
                      (start (point)))
                  (re-search-backward
                   (concat check-cves-mode-cve-id-regexp "\\=") nil t)
                  (or (re-search-backward check-cves-mode-cve-id-regexp nil t)
                      (progn (goto-char start)
                             (user-error "No more matches")))))
      (goto-char (match-beginning 0))
      (cl-decf arg))))

;;;###autoload
(defun check-cves-mode-modify (action)
  "Modify the current CVE with ACTION."
  (save-excursion
    (beginning-of-line)
    (re-search-forward (concat check-cves-mode-cve-id-regexp "\\(.*\\)$") nil t)
    (replace-match (concat " " action) t nil nil 2)))

(defvar check-cves-mode-source-packages
  (split-string
   (shell-command-to-string "umt grep '.*'")))

(defvar check-cves-mode-binary-packages
  (split-string
   (shell-command-to-string "dpkg-query --show --showformat '${Package}\n'")))

(defun check-cves-mode-prompt-for-packages (&optional chosen)
  "Prompt user for a list of source packages excluding CHOSEN."
  (let ((chosen chosen)
        (pkg))
    (while
        (progn
          (setq pkg (completing-read (concat "Package (" (string-join chosen " ") "): ")
                                     ;; don't offer the same package more than
                                     ;; once
                                     check-cves-mode-source-packages
                                     #'(lambda (p) (not (member p chosen)))
                                     nil))
          ;; stop if empty string selected
          (not (string-match-p "^\\s-*$" pkg)))
      (cl-pushnew pkg chosen :test #'string=))
    ;; reverse as cl-pushnew adds to head
    (reverse chosen)))

(defun check-cves-mode-add-or-edit (add-or-edit &optional priority packages)
  "ADD-OR-EDIT the current CVE with PRIORITY against PACKAGES."
  (save-excursion
    ;; find the current CVE
    (beginning-of-line)
    (re-search-forward (concat check-cves-mode-cve-id-regexp "\\(.*\\)$") nil t)
    (let ((end (progn (forward-line) (point))))
      (forward-line -1)
      (beginning-of-line)
      (when (re-search-forward
             (concat check-cves-mode-cve-id-regexp
                     " \\(add\\|edit\\) \\([a-z]+\\) \\(.*\\)")
             end t)
        (setq priority (match-string 3))
        (setq packages (cl-remove-if #'string-empty-p (split-string (match-string 4) " "))))))
  (unless priority
    (setq priority (completing-read "Priority: " check-cves-mode-priorities)))
  (setq packages (check-cves-mode-prompt-for-packages packages))
  (check-cves-mode-modify (concat add-or-edit " " priority " "
                                  (mapconcat #'identity packages " "))))

;;;###autoload
(defun check-cves-mode-add ()
  "Add the current CVE."
  (interactive)
  (check-cves-mode-add-or-edit "add"))

;;;###autoload
(defun check-cves-mode-edit ()
  "Edit the current CVE."
  (interactive)
  (check-cves-mode-add-or-edit "edit"))

;;;###autoload
(defun check-cves-mode-set-priority (priority)
  "Set the PRIORITY of the current CVE."
  (interactive
   (list
    (completing-read "Priority: " check-cves-mode-priorities)))
  (save-excursion
    ;; find the current CVE
    (beginning-of-line)
    (re-search-forward (concat check-cves-mode-cve-id-regexp "\\(.*\\)$") nil t)
    (let ((end (progn (forward-line) (point))))
      (forward-line -1)
      (beginning-of-line)
      (when (re-search-forward
             (concat check-cves-mode-cve-id-regexp
                     " \\(add\\|edit\\) \\([a-z]+\\)")
             end t)
        (replace-match priority t nil nil 3)))))

;;;###autoload
(defun check-cves-mode-repeat-previous ()
  "Repeat action etc from the previous CVE entry."
  (interactive)
  (let ((end (point))
        (details nil))
    (save-excursion
      (save-excursion
        (check-cves-mode-previous 1)
        (if (re-search-forward
             (concat check-cves-mode-cve-id-regexp "\\(.*\\)$") end t)
            (setq details (match-string 2))
          (user-error "No previous CVE to repeat")))
      ;; find the current CVE
      (beginning-of-line)
      (re-search-forward
       (concat check-cves-mode-cve-id-regexp "\\(.*\\)$") nil t)
      (replace-match details t nil nil 2))))

(defvar check-cves-mode-ignore-history
  nil
  "History for ignore reasons.")

(defun check-cves-mode-suggested-names ()
  "Find suggested names for the current CVE."
  (save-excursion
    ;; find the CVE ID
    (beginning-of-line)
    (re-search-forward (concat check-cves-mode-cve-id-regexp "\\(.*\\)$") nil t)
    (let ((cve (substring-no-properties (match-string 1)))
          (names nil)
          (start nil))
      ;; find start of the current CVE block
      (save-excursion
        (re-search-backward (concat "^# " cve "$"))
        (setq start (point)))
      (forward-line)
      ;; could use the suggested ignore text or package name
      (let ((priorities (append (mapcar #'car check-cves-mode-priorities)
                                check-cves-mode-invalid-priorities)))
        (while (re-search-backward
                (concat "^\\(# \\)?" cve
                        " \\(ignore\\|add " (regexp-opt priorities) "\\)"
                        " \\(.*\\)$") start t)
          ;; strip any quotes
          (let ((line (replace-regexp-in-string
                       "\"" "" (substring-no-properties (match-string 3)))))
            ;; push line first so ends up last since we reverse below so will end
            ;; up at head of the list end the end
            (cl-pushnew line names :test #'string=)
            (let ((words (split-string line)))
              (when (> (length words) 0)
                ;; push each element so can choose to search for some
                (mapc #'(lambda (word)
                          (cl-pushnew word names :test #'string=))
                      words))))))
      (reverse names))))

(defun check-cves-mode-prompt-with-suggested-names (prompt &optional names history default)
  "Get the suggested NAMES from the ignore line for this CVE via PROMPT with HISTORY."
  (if (and names (symbolp names) (not (functionp names)))
      (setq names (eval names)))
  (list (completing-read prompt (or names (check-cves-mode-suggested-names))
                         nil nil nil history default)))

;;;###autoload
(defun check-cves-mode-ignore (reason)
  "Ignore the current CVE with REASON."
  (interactive
   (let ((names (check-cves-mode-suggested-names)))
     ;; if called with prefix are use the longest suggested as name as is
     (if current-prefix-arg
         (list (cl-first (seq-sort-by #'seq-length #'> names)))
       (check-cves-mode-prompt-with-suggested-names
        "Reason: " names 'check-cves-mode-ignore-history))))
  (check-cves-mode-modify (concat "ignore " reason))
  (add-to-list 'check-cves-mode-ignore-history reason))

;;;###autoload
(defun check-cves-mode-skip ()
  "Skip the current CVE."
  (interactive)
  (check-cves-mode-modify "skip"))

(defvar check-cves-mode-browse-sources
  '(("MITRE"  . "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-%s")
    ("NIST"   . "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-%s")
    ("Debian" . "https://security-tracker.debian.org/tracker/CVE-%s")
    ("Redhat" . "https://access.redhat.com/security/cve/CVE-%s")
    ("RedHatBugzilla" . "https://bugzilla.redhat.com/show_bug.cgi?id=CVE-%s")
    ("Ubuntu" . "https://people.canonical.com/~ubuntu-security/cve/CVE-%s")
    ("Google" . "https://www.google.com/search?q=\"CVE-%s\"")
    ("ExploitDB" . "https://www.exploit-db.com/search?cve=%s"))
  "Online sources to search for a CVE via `browse-url'.

Each one should consist of a name for the source and a URL
template where %s will be replaced by the numeric CVE
identifier (XXXX-YYYY) via `format'.")

;;;###autoload
(defun check-cves-mode-browse ()
  "Browse the current CVEs CONFIRM / MISC URLs."
  (interactive
   ;; find potential URLs
   (save-excursion
     (let ((end))
       ;; find the start CVE ID
       (beginning-of-line)
       (re-search-forward
        (concat check-cves-mode-cve-id-regexp "\\(.*\\)$") nil t)
       (let* ((cve (substring-no-properties (match-string 1) 4))
              (urls (mapcar #'(lambda (source)
                                (concat (car source) ": "
                                        (format (cdr source) cve)))
                            check-cves-mode-browse-sources)))
         (setq end (point))
         (goto-char (point-min))
         (re-search-forward cve)
         ;; ensure to exclude newline from captured URL
         (while (re-search-forward
                 "\\(\\([A-Z]+: \\)?\\(https?://[^[:blank:]\n]+\\)\\).*$"
                 end t)
           (cl-pushnew (substring-no-properties (match-string 1)) urls
                       :test #'string=))
         ;; reverse as cl-pushnew adds to head
         (let ((choice (completing-read "Browse URL: " (reverse urls) nil t)))
           (let ((end (string-match "\\(https?://[^[:blank:]]+\\)" choice)))
             (browse-url (substring-no-properties choice end)))))))))

(defconst check-cves-mode-base-path
  (file-name-directory
   (file-truename
    (expand-file-name
     (or load-file-name buffer-file-name)))))

(defvar check-cves-mode-search-tools
  `((:name "apt show"
           :command  "apt show %s"
           :downcase t
           :mode  compilation-mode
           :candidates check-cves-mode-binary-packages)
    (:name "apt showsrc"
           :command  "apt showsrc %s"
           :downcase t
           :mode  compilation-mode
           :candidates check-cves-mode-source-packages)
    (:name "apt search (host)"
           :command  "apt search %s"
           :mode  compilation-mode)
    (:name "apt search (in all schroots)"
           :command  "schroot-cmd apt search %s"
           :mode  compilation-mode)
    (:name "apt-file search"
           :command  "apt-file search %s"
           :downcase t
           :mode  compilation-mode)
    (:name "codesearch-cli"
           :command  "codesearch-cli -q -- \"%s\""
           :mode codesearch-cli-mode)
    (:name "rmadison"
           :command  "rmadison %s"
           :downcase t
           :mode  compilation-mode
           :candidates check-cves-mode-source-packages)
    (:name "umt grep"
           :command "umt grep %s"
           :downcase t
           :mode compilation-mode)
    (:name "umt search"
           :command "umt search %s"
           :downcase t
           :mode compilation-mode
           :candidates check-cves-mode-source-packages)
    (:name "command-not-found"
           :command "/usr/lib/command-not-found %s"
           :downcase t
           :mode compilation-mode)
    (:name "not-for-us"
           :function grep
           :args ,(concat "grep -i '%s' "
                          check-cves-mode-base-path
                          "../ignored/not-for-us.txt")))
  "List of tools to search with and the mode to display the results.")

(defvar codesearch-cli-results-regexp-alist
  '("^path: \\(\\([^_]+\\)_\\([^/]+\\)/\\(.*\\)\\)" 4)
  "Regular expression alist to match against for results from codesearch-cli.")

(defun codesearch-cli-mode-bug-reference-url-format ()
  "Format results from codesearch-cli as links to sources.debian.org."
  (format "https://sources.debian.org/src/%s/%s/%s/"
          (match-string 2) (match-string 3) (match-string 4)))

(defun codesearch-cli-mode-copy-source-packages ()
  "Get the source packages listed in the current buffer."
  (interactive)
  (save-excursion
    (goto-char (point-min))
    (let ((packages))
      (while (re-search-forward (car codesearch-cli-results-regexp-alist) nil t)
        (cl-pushnew (match-string 2) packages :test #'string=))
      (kill-new (string-join (reverse packages) " ")))))

(define-derived-mode codesearch-cli-mode compilation-mode "codesearch-cli-"
  "codesearch-cli-mode is a major mode for viewing the output of codesearch-cli."
  ;; linkify results back to sources.debian.org
  (set (make-local-variable 'compilation-error-regexp-alist)  (list codesearch-cli-results-regexp-alist))
  (set (make-local-variable 'bug-reference-url-format) #'codesearch-cli-mode-bug-reference-url-format)
  (set (make-local-variable 'bug-reference-bug-regexp) (car codesearch-cli-results-regexp-alist))
  (bug-reference-mode 1))

(defun check-cves-mode-find-search-tool (tool-name)
  "Find the entry from `check-cves-mode-search-tools' with TOOL-NAME."
  (let ((tool))
    (dolist (tl check-cves-mode-search-tools)
      (when (string= (plist-get tl :name) tool-name)
        (setq tool tl)))
    tool))

;;;###autoload
(defun check-cves-mode-search (tool-name keywords)
  "Search the current CVEs KEYWORDS with TOOL-NAME (apt / umt etc)."
  (interactive
   (let* ((name (completing-read "Tool: "
                                 (mapcar #'(lambda (e) (plist-get e :name))
                                         check-cves-mode-search-tools)
                                 nil t))
          (tool (check-cves-mode-find-search-tool name)))
     (list
      name
      (check-cves-mode-prompt-with-suggested-names "Keywords: "
                                                   (plist-get tool :candidates)
                                                   nil (check-cves-mode-suggested-names)))))
  (let ((tool (check-cves-mode-find-search-tool tool-name))
        (words (mapconcat #'identity keywords " ")))
    (unless tool
      (user-error "Unknown tool '%s'" tool-name))
    (when (plist-get tool :downcase)
      (setq words (downcase words)))
    (if (plist-get tool :function)
        ;; use function with arguments
        (funcall (plist-get tool :function)
                 (format (plist-get tool :args) words))
      ;; otherwise spawn process via command
      (let* ((command (plist-get tool :command))
             (mode (plist-get tool :mode))
             (buffer (get-buffer-create
                      (format "*check-cves-mode-search-%s*" tool-name)))
             (proc (progn
                     (async-shell-command
                      (format command words) buffer)
                     (get-buffer-process buffer))))
        (if (and (process-live-p proc) mode)
            ;; only set mode once process is complete
            (set-process-sentinel
             proc #'(lambda (proc signal)
                      (when (memq (process-status proc) '(exit signal))
                        (with-current-buffer buffer
                          (funcall mode)
                          ;; highlight occurrences automatically
                          (font-lock-add-keywords
                           nil
                           (mapcar (lambda (k) `(,k . font-lock-warning-face))
                                   keywords))))
                      (shell-command-sentinel proc signal))))))))

;;;###autoload
(defun check-cves-mode-occur ()
  "Use `occur' to find all CVEs."
  (interactive)
  (occur check-cves-mode-cve-id-regexp))

(defun check-cves-mode-get-source-package-details (package)
  "Return details for source PACKAGE."
  (shell-command-to-string
   (concat "umt search " package "| "
           ;; strip initial few lines output
           "tail -n+5 | "
           ;; and stop after the first blank line to only
           ;; show ubuntu package info
           "sed '/^$/q' | "
           ;; and join into a single line
           "tr '\n' ' '")))

(defun check-cves-mode-get-documentation-for-term (term)
  "Return documentation for TERM."
  (cond ((member term (mapcar #'car check-cves-mode-actions))
         (alist-get term check-cves-mode-actions nil nil #'string=))
        ((member term (mapcar #'car check-cves-mode-priorities))
         (alist-get term check-cves-mode-priorities nil nil #'string=))
        ((member term check-cves-mode-source-packages)
         (check-cves-mode-get-source-package-details term))
        (t nil)))

(defun check-cves-mode-completion-at-point ()
  "`completion-at-point' function for check-cves-mode."
  ;; see what we should complete
  (let ((candidates))
    (save-excursion
      (beginning-of-line)
      (setq candidates
            (cond ((looking-at (concat check-cves-mode-cve-id-regexp " "
                                       (regexp-opt (list "add" "edit")) " "
                                       (regexp-opt (mapcar #'car check-cves-mode-priorities))))
                   (setq candidates check-cves-mode-source-packages))
                  ((looking-at (concat check-cves-mode-cve-id-regexp " "
                                       (regexp-opt (list "add" "edit"))))
                   (setq candidates (mapcar #'car check-cves-mode-priorities)))
                  ((looking-at check-cves-mode-cve-id-regexp)
                   (setq candidates (mapcar #'car check-cves-mode-actions)))
                  (t nil))))
    (let ((bounds (bounds-of-thing-at-point 'symbol)))
      (list (car bounds) ; start
            (cdr bounds) ; end
            candidates
            :company-docsig #'identity
            :company-doc-buffer #'(lambda (term)
                                    (let ((doc (check-cves-mode-get-documentation-for-term term)))
                                      (when doc (company-doc-buffer doc))))))))

(defun check-cves-mode-eldoc-function ()
  "Support for eldoc mode."
  ;; only get first line
  (let ((doc (check-cves-mode-get-documentation-for-term (thing-at-point 'symbol))))
    (when doc
      (setq doc (substring doc 0 (string-match "\n" doc))))))

(defvar check-cves-mode-map
  (let ((map (make-sparse-keymap)))
    (define-key map (kbd "M-n") #'check-cves-mode-next)
    (define-key map (kbd "M-p") #'check-cves-mode-previous)
    ;; prefix actions with C-c C-mnemonic
    (define-key map (kbd "C-c C-a") #'check-cves-mode-add)
    (define-key map (kbd "C-c C-e") #'check-cves-mode-edit)
    (define-key map (kbd "C-c C-i") #'check-cves-mode-ignore)
    (define-key map (kbd "C-c C-s") #'check-cves-mode-skip)
    (define-key map (kbd "C-c C-b") #'check-cves-mode-browse)
    (define-key map (kbd "C-c C-f") #'check-cves-mode-search)
    (define-key map (kbd "C-c C-p") #'check-cves-mode-set-priority)
    (define-key map (kbd "C-c C-r") #'check-cves-mode-repeat-previous)
    map)
  "Keymap for `check-cves-mode'.")

;;;###autoload
(define-derived-mode check-cves-mode text-mode "CVEs"
  "check-cves-mode is a major mode for editing the output from check-cves in UCT."
  :syntax-table check-cves-mode-syntax-table
  (setq font-lock-defaults check-cves-mode-font-lock-defaults)
  (add-to-list 'completion-at-point-functions #'check-cves-mode-completion-at-point)
  (add-function :before-until (local 'eldoc-documentation-function)
                #'check-cves-mode-eldoc-function)
  ;; turn on eldoc since is not in text-mode by default
  (eldoc-mode 1)
  (setq comment-start "#")
  (setq comment-end "")
  ;; linkify URLs
  (goto-address-mode 1)
  ;; highlight current line
  (hl-line-mode 1)
  ;; linkify CVEs
  (set (make-local-variable 'bug-reference-url-format) "https://people.canonical.com/~ubuntu-security/cve/%s.html")
  (set (make-local-variable 'bug-reference-bug-regexp) "\\(\\(CVE-[[:digit:]]\\{4\\}-[[:digit:]]\\{4,\\}\\)\\)")
  (bug-reference-mode 1))

;;;###autoload
(add-to-list 'auto-mode-alist '("check-cves\\..*\\'" . check-cves-mode))

(provide 'check-cves-mode)
;;; check-cves-mode.el ends here
