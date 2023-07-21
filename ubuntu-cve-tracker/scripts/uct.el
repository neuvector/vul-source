;;; uct -- Emacs interface to the Ubuntu CVE tracker  -*- lexical-binding: t -*-

;;; Commentary:

;;; Code:
(require 'cl-lib)
(require 'subr-x)
(require 'cve-mode)
(require 'org)
(require 'grep)

(defgroup uct nil
  "UCT for Emacs"
  :group 'applications)

(defconst uct-directories '("active" "embargoed" "ignored" "retired"))

(defconst uct-cve-regex cve-mode-cve-id-regexp)

(defconst uct-cve-filename-regex (concat "^" uct-cve-regex "$"))

(defcustom uct-cve-limit 1000
  "The maximum number of CVEs to show.
Note, this affects performance quite a bit so beware.  Set to -1
for no limits."
  :group 'uct
  :type 'integer)

(defvar uct-cves nil)

(defvar uct-inotify-watch-descriptors nil)

(defvar uct-description-regexp "")

(defvar uct-supported-releases
  (mapcar #'intern cve-mode-releases))

(defvar uct-selected-sources '(active embargoed))

(defvar uct-selected-statuses '(needs-triage needed deferred pending))

(defvar uct-selected-priorities nil)

(defvar uct-selected-packages nil)

(defvar uct-selected-assignees nil)

(defconst uct-base-path
  (file-name-directory
   (directory-file-name
    (file-name-directory
     (file-truename
      (expand-file-name
       (or load-file-name buffer-file-name)))))))

(cl-defstruct (cve (:constructor cve-create)
                   (:copier nil))
  (id nil :read-only t)
  (description nil :read-only t)
  (priority nil :read-only t)
  (assignee nil :read-only t)
  (package nil :read-only t)
  (status nil :read-only t)
  (file nil :read-only t))

(defun cve-source (cve)
  "Return the source for CVE."
  (intern (car
           (last
            (split-string
             (directory-file-name
              (file-name-directory
               (cve-file cve)))
             "/")))))

(defun uct--flatten (l)
  "Flatten list L."
  (cond ((null l) l)
        ((listp l) (append (uct--flatten (car l)) (uct--flatten (cdr l))))
        (t (list l))))

(defun uct-load-cves-from-file (file)
  "Load all CVEs from FILE and return `cve' objects or nil on error."
  (let (id description priority assignee packages)
    (with-temp-buffer
      (insert-file-contents file)
      (goto-char (point-min))
      (save-excursion
        (if (re-search-forward (concat "^Candidate: *" uct-cve-regex) nil t)
            (setq id (intern (match-string 1)))
          (error "%s does not appear to be a valid CVE" file)))
      (save-excursion
        (setq description
              (if (re-search-forward "^Description: *" nil t)
                  (let ((start (point))
                        (end (progn
                               (re-search-forward "^[A-Z]")
                               (forward-line -1)
                               (end-of-line)
                               (point))))
                    ;; unify all whitespace for spaces
                    (replace-regexp-in-string
                     "\\s-+" " "
                     (string-trim (buffer-substring-no-properties start end))))
                "")))
      (save-excursion
        (if (re-search-forward cve-mode-priority-regexp nil t)
            (setq priority (intern (match-string 1)))
          (setq priority '-)))
      (save-excursion
        (if (re-search-forward cve-mode-assigned-to-regexp nil t)
            (setq assignee (intern (match-string 1)))
          (setq assignee '-)))
      (while (re-search-forward (concat cve-mode-releases-regexp
                                        " \\([a-z-]+\\)") nil t)
        (let* ((release (intern (match-string 1)))
               (package (intern (match-string 2)))
               (status (intern (or (match-string 3) "untriaged")))
               (entry (assoc package packages))
               (statuses (cdr entry)))
          (if entry
              (setf (cdr entry)
                    (push `(,release . ,status) statuses))
            (push `(,package . ,statuses) packages))))
      (mapcar #'(lambda (pkg)
                  (cve-create :id id
                              :description description
                              :priority priority
                              :assignee assignee
                              :package (car pkg)
                              :status (cdr pkg)
                              :file file))
              packages))))

(defun uct-find-cves (dir)
  "Return all CVEs found in DIR."
  (let* ((cves nil)
         (i 0)
         (files (directory-files dir t uct-cve-filename-regex))
         (progress (make-progress-reporter
                    (format "Loading CVEs from %s..." dir) 1 (length files))))
    (dolist (file files)
      (cl-incf i)
      (progress-reporter-update progress i)
      (dolist (cve (uct--flatten (uct-load-cves-from-file file)))
        (push cve cves)))
    (progress-reporter-done progress)
    cves))

(defface uct-list-face-cve-active
  '((t :inherit font-lock-function-name-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-cve-embargoed
  '((t :inherit error))
  "Face used on the status of CVEs.")

(defface uct-list-face-cve-retired
  '((t :inherit font-lock-comment-face))
  "Face used on the status of CVEs.")

(defun uct-list--face-for-cve (cve)
  "Return face for CVE."
  (let ((dir (file-name-base
              (directory-file-name
               (file-name-directory (cve-file cve))))))
    (pcase dir
      (`"active" 'uct-list-face-cve-active)
      (`"embargoed" 'uct-list-face-cve-embargoed)
      (`"retired" 'uct-list-face-cve-retired)
      (_ 'font-lock-warning-face))))

(defface uct-list-face-priority-critical
  '((t :inherit error))
  "Face used on the status of CVEs.")

(defface uct-list-face-priority-high
  '((t :inherit font-lock-warning-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-priority-medium
  '((t :inherit default))
  "Face used on the status of CVEs.")

(defface uct-list-face-priority-low
  '((t :inherit font-lock-comment-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-priority-negligible
  '((t :inherit font-lock-comment-face))
  "Face used on the status of CVEs.")

(defun uct-list--face-for-priority (priority)
  "Return face for PRIORITY."
  (pcase priority
    (`critical 'uct-list-face-priority-critical)
    (`high 'uct-list-face-priority-high)
    (`medium 'uct-list-face-priority-medium)
    (`low 'uct-list-face-priority-low)
    (`negligible 'uct-list-face-priority-negligible)
    (_ 'font-lock-warning-face)))

(defface uct-list-face-status-dne
  '((t :inherit font-lock-comment-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-status-not-affected
  '((t :inherit font-lock-comment-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-status-needs-triage
  '((t :inherit default))
  "Face used on the status of CVEs.")

(defface uct-list-face-status-needed
  '((t :inherit font-lock-warning-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-status-deferred
  '((t :inherit font-lock-builtin-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-status-pending
  '((t :inherit font-lock-function-name-face))
  "Face used on the status of CVEs.")

(defface uct-list-face-status-released
  '((t :inherit font-lock-keyword-face))
  "Face used on the status of CVEs.")

(defun uct-list--face-for-status (status)
  "Return face for STATUS."
  (pcase status
    (`DNE 'uct-list-face-status-dne)
    (`not-affected 'uct-list-face-status-not-affected)
    (`needs-triage 'uct-list-face-status-needs-triage)
    (`needed 'uct-list-face-status-needed)
    (`deferred 'uct-list-face-status-deferred)
    (`pending 'uct-list-face-status-released)
    (`released 'uct-list-face-status-released)
    (_ 'font-lock-warning-face)))

(defun uct-list-load-entry (&optional button)
  "Load a CVE from the CVE list.
If optional arg BUTTON is non-nil, describe it's associated CVE."
  (interactive)
   (unless (derived-mode-p 'uct-list-mode)
     (error "The current buffer is not in UCT List Mode"))
   (let ((cve (if button (button-get button 'cve)
               (tabulated-list-get-id))))
    (if cve
        (find-file-other-window (cve-file cve))
      (user-error "No CVE here"))))

(defun uct-list--list-entry (cve)
  "Return a CVE entry suitable for `tabulated-list-entries'.
CVE is a `cve' object."
  (list cve
        `[(,(symbol-name (cve-id cve))
           face ,(uct-list--face-for-cve cve)
           follow-link t
           cve ,cve
           action uct-list-load-entry)
          ,(symbol-name (cve-package cve))
          ,(propertize (symbol-name (cve-priority cve))
                       'font-lock-face
                       (uct-list--face-for-priority (cve-priority cve)))
          ,@(mapcar #'(lambda (release)
                        (let ((status (or (cdr (assoc release (cve-status cve))) '-)))
                          (propertize (symbol-name status)
                                      'font-lock-face
                                      (uct-list--face-for-status status))))
                    uct-supported-releases)
          ,(propertize (cve-description cve)
                       'font-lock-face 'font-lock-string-face)]))

(defun uct-list--status-selected (cve)
  "Whether CVE has any status listed in `uct-selected-statuses'."
  (cl-notevery #'null
             (mapcar #'(lambda (release)
                         (let ((status (or (cdr (assoc release (cve-status cve))) '-)))
                           (memq status uct-selected-statuses)))
                     uct-supported-releases)))

(defun uct-list--visible (cve)
  "Whether CVE should be visible in list or not."
  (and
   (or (null uct-selected-assignees)
       (member (cve-assignee cve) uct-selected-assignees))
   (or (null uct-selected-packages)
       (member (cve-package cve) uct-selected-packages))
   (or (null uct-selected-sources)
       (member (cve-source cve) uct-selected-sources))
   (or (null uct-selected-statuses)
       (uct-list--status-selected cve))
   (or (null uct-selected-priorities)
       (member (cve-priority cve) uct-selected-priorities))
   (string-match-p uct-description-regexp (cve-description cve))))

(defun uct-list-inotify-event (event)
  "Callback for inotofy EVENTs on CVE directories."
  (let ((descriptor (cl-first event))
        (aspects (cl-second event))
        (name (cl-third event))
        (buffer (get-buffer "*UCT*"))
        (filename nil))
    (when (string-match-p uct-cve-filename-regex name)
      ;; get full filename
      (dolist (d uct-inotify-watch-descriptors)
          (when (equal (car d) descriptor)
            (setq filename (expand-file-name name (cdr d)))))
      ;; remove and reparse for now
      (dolist (cve uct-cves)
        (when (string= (cve-file cve) filename)
          (setq uct-cves (delete cve uct-cves))))
      (when (or (member 'create aspects)
                (member 'modify aspects))
        (dolist (cve (uct-load-cves-from-file filename))
          (push cve uct-cves)))
      (when buffer
        (with-current-buffer buffer
          (tabulated-list-revert))))))

(defun uct-list-new ()
  "Create a new CVE for the package of the entry at point."
  (interactive)
  (unless (derived-mode-p 'uct-list-mode)
    (error "The current buffer is not in UCT List Mode"))
  (uct-new-cve (read-string "CVE: ")
               (list (symbol-name (cve-package (tabulated-list-get-id))))))

(defun uct-list-refresh ()
  "Refresh the list of CVEs from `uct-directories'."
  (interactive)
  (unless (derived-mode-p 'uct-list-mode)
    (error "The current buffer is not in UCT List Mode"))
  (tabulated-list-init-header)
  ;; don't try and mapcar as run out of stack depth - accumulate and
  ;; process
  (let ((entries)
        (n 0))
    ;; load cves on demand if we don't have any yet
    (unless uct-cves
      ;; ensure no stale watches
      (mapc #'(lambda (d)
                (inotify-rm-watch (car d))) uct-inotify-watch-descriptors)
      (setq uct-inotify-watch-descriptors nil)
      (message "Loading CVEs from %s..."
               (mapconcat #'identity uct-directories ", "))
      (dolist (dir (mapcar #'(lambda (d) (expand-file-name d uct-base-path))
                           uct-directories))
        (dolist (cve (uct-find-cves dir))
          (push cve uct-cves))
        ;; watch for updates to files in dir - TODO should we add delete,
        ;; move or other aspects?
        (let ((descriptor (inotify-add-watch dir '(create delete modify onlydir)
                                             #'uct-list-inotify-event)))
          (add-to-list 'uct-inotify-watch-descriptors
                       (cons descriptor dir)))))
    (dolist (cve uct-cves)
      (when (and (or (< uct-cve-limit 0)
                     (< n uct-cve-limit))
                 (uct-list--visible cve))
        (push (uct-list--list-entry cve) entries)
        (cl-incf n)))
    (setq tabulated-list-entries entries))
  (setq mode-name (concat (format "%d CVEs"
                                  (length tabulated-list-entries))
                          (when (> (length uct-description-regexp) 0)
                            (concat " \"" uct-description-regexp "\""))
                          (when uct-selected-assignees
                            (concat " <"
                                    (mapconcat #'symbol-name uct-selected-assignees ", " )
                                    ">"))
                          (when uct-selected-statuses
                            (concat " {"
                                    (mapconcat #'symbol-name uct-selected-statuses ", " )
                                    "}"))
                          (when uct-selected-sources
                                     (concat " ["
                                             (mapconcat #'symbol-name uct-selected-sources ", " )
                                             "]"))
                          (when uct-selected-packages
                                     (concat " ("
                                             (mapconcat #'symbol-name uct-selected-packages ", " )
                                             ")")))))

(defun uct-list--id-predicate (A B)
  "Sort predicate for CVE on ID between A and B."
  (string< (cve-id (car A)) (cve-id (car B))))

(defvar uct-list--priorities '(negligible low medium high critical))

(defun uct-list--priority-predicate (A B)
  "Sort predicate for CVE priority between A and B."
  (< (or (cl-position (cve-priority (car A)) uct-list--priorities) -1)
     (or (cl-position (cve-priority (car B)) uct-list--priorities) -1)))

(defun uct-list--get-packages ()
  "Return the list of packages from the current list of CVEs."
  (let (packages)
    (dolist (cve uct-cves)
      (let ((package (cve-package cve)))
        (unless (member package packages)
          (push package packages))))
    packages))

(defun uct-list--get-assignees ()
  "Return the list of assignees from the current list of CVEs."
  (let (assignees)
    (dolist (cve uct-cves)
      (let ((assignee (cve-assignee cve)))
        (unless (member assignee assignees)
          (push assignee assignees))))
    assignees))

(defun uct-list--prompt-for-items (prompt items)
  "PROMPT user for a list of ITEMS."
  (let ((chosen nil)
        (item))
    ;; ensure items are atoms not strings
    (while
        (progn
          (setq item (completing-read
                      ;; show user the items already selected
                      (concat prompt
                              " (" (mapconcat #'symbol-name chosen ", ") "): ")
                      ;; ensure we work with atoms not strings
                      (mapcar #'(lambda (i) (if (stringp i) (intern i) i)) items)
                      ;; don't offer the same item more
                      ;; than once
                      #'(lambda (i) (not (member i chosen)))
                      nil))
          ;; stop if empty string selected
          (not (string-match-p "^\\s-*$" item)))
      (cl-pushnew (intern item) chosen))
    ;; reverse as cl-pushnew adds to head
    (reverse chosen)))

(defun uct-list-filter-by-packages (&optional packages)
  "Filter the list of CVEs to only those affecting PACKAGES.
If called with a prefix argument, filter to only the current CVEs package."
  (interactive
   ;;
   (list (if current-prefix-arg
             (list (cve-package (tabulated-list-get-id)))
           (uct-list--prompt-for-items "Packages" (uct-list--get-packages)))))
  (unless (derived-mode-p 'uct-list-mode)
    (error "The current buffer is not in UCT List Mode"))
  (unless (listp packages)
    (user-error "PACKAGES should be a list of packages to filter"))
  (setq uct-selected-packages packages)
  (tabulated-list-revert))

(defun uct-list-filter-by-sources (&optional sources)
  "Filter the list of CVEs to only those affecting SOURCES."
  (interactive
   (list (uct-list--prompt-for-items "Sources" uct-directories)))
   (unless (derived-mode-p 'uct-list-mode)
     (error "The current buffer is not in UCT List Mode"))
   (unless (listp sources)
     (user-error "SOURCES should be a list of sources to filter"))
   (setq uct-selected-sources sources)
  (tabulated-list-revert))

(defun uct-list-filter-by-statuses (&optional statuses)
  "Filter the list of CVEs to only those with a status in STATUSES."
  (interactive
   (list (uct-list--prompt-for-items "Statuses" cve-mode-statuses)))
   (unless (derived-mode-p 'uct-list-mode)
     (error "The current buffer is not in UCT List Mode"))
   (unless (listp statuses)
     (user-error "STATUSES should be a list of statuses to filter"))
   (setq uct-selected-statuses statuses)
  (tabulated-list-revert))

(defun uct-list-filter-by-priorities (&optional priorities)
  "Filter the list of CVEs to only those with a priority in PRIORITIES."
  (interactive
   (list (uct-list--prompt-for-items "Priorities"
                                     '(negligible low medium high critical))))
  (unless (derived-mode-p 'uct-list-mode)
    (error "The current buffer is not in UCT List Mode"))
  (unless (listp priorities)
    (user-error "PRIORITIES should be a list of priorities to filter"))
  (setq uct-selected-priorities priorities)
  (tabulated-list-revert))

(defun uct-list-filter-by-assignees (&optional assignees)
  "Filter the list of CVEs to only those assigned to ASSIGNEES."
  (interactive
   (list (uct-list--prompt-for-items "Assignees" (uct-list--get-assignees))))
   (unless (derived-mode-p 'uct-list-mode)
     (error "The current buffer is not in UCT List Mode"))
   (unless (listp assignees)
     (user-error "ASSIGNEES should be a list of assignees to filter"))
   (setq uct-selected-assignees assignees)
  (tabulated-list-revert))

(defun uct-list-filter-by-description (&optional regexp)
  "Filter the list of CVEs to only those with a description matching REGEXP."
  (interactive
   (list (read-string "Description regexp: " uct-description-regexp)))
  (unless (derived-mode-p 'uct-list-mode)
    (error "The current buffer is not in UCT List Mode"))
  (setq uct-description-regexp regexp)
  (tabulated-list-revert))

(defvar uct-list-mode-map
  (let ((map (make-sparse-keymap)))
    (set-keymap-parent map tabulated-list-mode-map)
    (define-key map "\C-m" 'uct-list-load-entry)
    (define-key map "c" 'uct-list-new)
    (define-key map "a" 'uct-list-filter-by-assignees)
    (define-key map "g" 'uct-list-refresh)
    (define-key map "P" 'uct-list-filter-by-packages)
    (define-key map "s" 'uct-list-filter-by-statuses)
    (define-key map "d" 'uct-list-filter-by-sources)
    (define-key map "i" 'uct-list-filter-by-priorities)
    (define-key map "/" 'uct-list-filter-by-description)
    map)
  "Local keymap for `uct-list-mode' buffers.")

;;;###autoload
(define-derived-mode uct-list-mode tabulated-list-mode "CVEs"
  "Major mode for browsing CVEs.
\\<uct-list-mode-map>
\\{uct-list-mode-map}"
  (setq tabulated-list-format `[("CVE" 17 uct-list--id-predicate)
                                ("Package" 18 t)
                                ("Priority" 10 uct-list--priority-predicate)
                                ,@(mapcar #'(lambda (release)
                                              (list (symbol-name release) 12 nil))
                                          uct-supported-releases)
                                ("Description" 0 nil)])
  (setq tabulated-list-sort-key (cons "CVE" nil))
  (add-hook 'tabulated-list-revert-hook #'uct-list-refresh nil t)
  (tabulated-list-init-header))

;;;###autoload
(defun uct ()
  "Display list of CVEs."
  (interactive)
  (let ((buffer (get-buffer-create "*UCT*")))
    (with-current-buffer buffer
      (uct-list-mode)
      (uct-list-refresh)
      (message "Displaying CVEs...")
      (tabulated-list-print))
    (switch-to-buffer buffer)))

;;;###autoload
(defun uct-cve-at-point ()
  "Return the CVE at point or nil if none found."
  (let ((cve (thing-at-point 'symbol t)))
    (when (or (null cve) (not (string-match uct-cve-filename-regex cve)))
      (save-excursion
        (let ((end (save-excursion (forward-line) (point))))
          (backward-word)
          (if (re-search-forward uct-cve-regex end t)
              (setq cve (substring-no-properties (match-string 1)))
            (setq cve nil)))))
    cve))

(defun uct-cve-priority (cve)
  "Return the priority of CVE."
  (let ((path (uct-cve-path cve)))
    (when path
        (symbol-name (cve-priority (car (uct-load-cves-from-file path)))))))

(defun uct-cve-path (cve)
  "Return the path for CVE if found in UCT or nil if not found."
  (let ((path nil))
    (when (and cve (string-match uct-cve-filename-regex cve))
      (dolist (dir '("active" "retired" "ignored" "embargoed"))
        (let ((file (format "%s/%s/%s" uct-base-path dir cve)))
          (when (file-exists-p file)
            (setq path file)))))
    path))

;;;###autoload
(defun uct-find-cve (&optional cve)
  "Open the specified CVE file from UCT (or if no CVE use the one at point).
If the specified CVE is not found in UCT will prompt to create it."
  (interactive (list (upcase (or (uct-cve-at-point) (read-string "CVE: ")))))
  (let ((path (uct-cve-path cve)))
          (if path
              (find-file-other-window path)
            ;; check if is in not-for-us.txt
            (let ((cmd (format "%s '\\\<%s\\\>' %s/ignored/not-for-us.txt"
                               (or grep-command "grep --color -nH --null -e ")
                               cve uct-base-path)))
              (if (> (length (shell-command-to-string cmd)) 0)
                  (grep cmd)
                (when (yes-or-no-p (format "%s not found in UCT. Do you want to create it?" cve))
                  (call-interactively #'uct-new-cve)))))))

(defvar uct--source-packages
  (split-string
   (shell-command-to-string "grep Package: /var/lib/apt/lists/*Sources | awk '{print $2}' | sort | uniq")))

(defun uct--read-multiple (prompt)
  "Read a list of multiple items form the user with PROMPT."
  (let ((chosen nil)
        (item))
    (while
        (progn
          (setq item (read-string prompt))
          ;; stop if empty string selected
          (not (string-match-p "^\\s-*$" item)))
      (cl-pushnew item chosen :test #'string=))
    ;; reverse as cl-pushnew adds to head
    (reverse chosen)))

(defun uct--read-from-list (prompt list)
  "Read a selection of items from LIST with PROMPT."
  (let ((chosen nil)
        (item))
    (while
        (progn
          (setq item (completing-read prompt
                                     ;; don't offer the same package more than
                                     ;; once
                                     list
                                     #'(lambda (p) (not (member p chosen)))
                                     nil))
          ;; stop if empty string selected
          (not (string-match-p "^\\s-*$" item)))
      (cl-pushnew item chosen :test #'string=))
    ;; reverse as cl-pushnew adds to head
    (reverse chosen)))

(defun uct--read-packages ()
  "Read a list of packages from the user."
  (uct--read-from-list "Packages: " uct--source-packages))

(defun uct-read-date-time (prompt)
  "Read a date and time from the user with PROMPT and output in UCT format."
  (let ((time (parse-time-string (org-read-date 'with-time nil nil prompt))))
    (format "%04d-%02d-%02d %02d:%02d:00 UTC"
                  (nth 5 time) (nth 4 time) (nth 3 time)
                  (or (nth 2 time) 0)
                  (or (nth 1 time) 0))))

;;;autoload
(defun uct-new-cve (&optional cve packages bugs urls public-date embargoed)
  "Create a new CVE entry in UCT.
PACKAGES should be a list of package name symbols - or for each
package a list containing the package name symbol, with an
optional version string where package is fixed (upstream) and
then optionally a Ubuntu release name and Ubuntu package version
containing the fix.

BUGS is a list of URLs to bug references for the CVE.

URLS is a list of URL references for the CVE.

PUBLIC-DATE is a string which specifies the date the CVE went
public.

EMBARGOED specifies whether the CVE entry should be in the
embargoed tree."
  (interactive (list (or (uct-cve-at-point) (read-string "CVE: "))
                     (uct--read-packages)
                     (uct--read-multiple "Bug reference: ")
                     (uct--read-multiple "URL: ")
                     (uct-read-date-time "Public date: " )
                     (yes-or-no-p "Embargoed? ")))
  (let ((args (list "-c" cve "-y"))
        (output (get-buffer-create "*active_edit*")))
    (dolist (package packages)
      (setq args (append args (list "-p" package))))
    (dolist (bug  bugs)
      (setq args (append args (list "-b" bug))))
    (dolist (url  urls)
      (setq args (append args (list "-r" url))))
    (when embargoed
      (push "-e" args))
    (when public-date
      (setq args (append args (list "-P" public-date))))
    ;; call call-process via apply so we can pass the list of arguments for active_edit as a
    ;; list itself rather than as individual arguments
    (apply #'call-process
           (expand-file-name
            "active_edit"
            (expand-file-name "scripts" uct-base-path))
           nil output t args)
    (uct-find-cve cve)))

;;;autoload
(defun uct-kernel-signoff (release kernel version)
  "Do the kernel signoff process for RELEASE KERNEL VERSION."
  (interactive "sRelease: \nsKernel: \nsVersion:")
  (let ((buffer (get-buffer-create (format "*uct-kernel-signoff-%s-%s-%s"
                                           release kernel version))))
    (cd uct-base-path)
    (async-shell-command (concat (expand-file-name
                                   "prepare-kernel-usn.py"
                                   (expand-file-name "scripts" uct-base-path))
                                 " -n --debug -p Proposed " release " " kernel " " version)
                         buffer buffer)
    (switch-to-buffer buffer)))

;;;autoload
(defun uct-kernel-signoff-at-point ()
  "Do uct-kernel-signoff for the info at point."
  (interactive)
  (save-excursion
    (beginning-of-line)
    (if (re-search-forward "\\([a-z]\+\\) \\([a-z0-9/.-]\+:\\) \\([0-9.~-]\+\\)")
        (uct-kernel-signoff (match-string 1) (match-string 2) (match-string 3))
      (user-error "Could not find RELEASE KERNEL VERSION"))))

;;;autoload
(defun uct-process-cves (&optional arg)
  "Run ./scripts/process_cves from UCT with ARG."
  (interactive "sArgs: ")
  (let ((compilation-buffer-name-function #'(lambda (_) "*uct-process-cves*"))
        (default-directory uct-base-path))
    (compile (concat (expand-file-name "process_cves"
                                       (expand-file-name "scripts"
                                                         uct-base-path))
                     " " (or arg ""))
             t)))

;;;autoload
(defun uct-check-cves-from-maildir (maildir)
  "Run ./scripts/check-cves with MAILDIR"
    (interactive "DMaildir: ")
    (let ((buffer (get-buffer-create "*uct-check-cves-from-maildir*"))
          (default-directory uct-base-path))
      (async-shell-command (concat (expand-file-name
                                    "check-cves"
                                    (expand-file-name "scripts" uct-base-path))
                                   " --mbox " maildir)
                           buffer buffer)
      (switch-to-buffer buffer)))

;;;autoload
(defun uct-mistriaged-cves (&optional arg)
  "Run ./scripts/report-mistriaged-cves.py from UCT with ARG."
  (interactive)
  (let ((buffer (get-buffer-create "*uct-mistriaged-cves*"))
        (default-directory uct-base-path))
    (async-shell-command (concat (expand-file-name "report-mistriaged-cves.py"
                                                    (expand-file-name "scripts"
                                                                      uct-base-path))
                                 " " (or arg ""))
                          buffer buffer)
    (switch-to-buffer buffer)))

(declare-function magit-process-kill-on-abort "magit-process")

;;;autoload
(defun uct-magit-process-check-syntax-prompt-hook (proc str)
  "Hook function to handle check-syntax git commit hook prompt in STR from PROC."
  (let* ((prompt "Found syntax errors. Enter \"ignore\" to continue or anything else to exit: ")
         (resize-mini-windows t))
    (when (string-match prompt str)
      (process-send-string
       proc
       (concat
        (magit-process-kill-on-abort proc
          (read-string prompt))
        "\n")))))

(provide 'uct)
;;; uct.el ends here
