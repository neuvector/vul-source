;;; cvss-mode.el --- Minor mode for CVSS handling        -*- lexical-binding: t; -*-

;; Copyright (c) 2020 Alex Murray

;; Author: Alex Murray <alex.murray@canonical.com>
;; Maintainer: Alex Murray <alex.murray@canonical.com>
;; URL: https://launchpad.net/ubuntu-cve-tracker
;; Version: 0.1
;; Package-Requires: ((emacs "25.1"))

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

;; (require 'cvss-mode)
;; (cvss-mode 1)

;;; Code:
(require 'cl-lib)
(require 'eldoc)
(require 'thingatpt)

(cl-defstruct (cvss (:type list))
  "CVSS 3.x"
  (attack-vector nil :read-only t)
  (attack-complexity nil :read-only t)
  (privileges-required nil :read-only t)
  (user-interaction nil :read-only t)
  (scope nil :read-only t)
  (confidentiality-impact nil :read-only t)
  (integrity-impact nil :read-only t)
  (availability-impact nil :read-only t))

(defvar cvss-attack-vectors '((network . 0.85)
                              (adjacent . 0.62)
                              (local . 0.55)
                              (physical . 0.2)))
(defvar cvss-attack-complexities '((low . 0.77)
                                   (high . 0.44)))
(defvar cvss-privileges '((none . 0.85)
                          ;; scope (unchanged changed)
                          (low . (0.62 0.68))
                          (high . (0.27 0.5))))
(defvar cvss-user-interactions '((none . 0.85)
                                 (required . 0.62)))
(defvar cvss-scopes '(changed
                      unchanged))
(defvar cvss-cias '((high . 0.56)
                    (low . 0.22)
                    (none . 0.0)))
(defvar cvss-severities ' ((critical . (9.0 10.0))
                           (high . (7.0 8.9))
                           (medium . (4.0 6.9))
                           (low . (0.1 3.9))
                           (none . (0.0 0.0))))

(defun cvss-calculate-scores (cvss)
  "Return a list containing the base, exploitability and impact scores for CVSS."
  (let* ((iss (- 1 (* (- 1 (alist-get (cvss-confidentiality-impact cvss) cvss-cias))
                     (- 1 (alist-get (cvss-integrity-impact cvss) cvss-cias))
                     (- 1 (alist-get (cvss-availability-impact cvss) cvss-cias)))))
         (impact (if (eq (cvss-scope cvss) 'unchanged)
                     (* 6.42 iss)
                   (- (* 7.52 (- iss 0.029)) (* 3.25 (expt (- iss 0.02) 15)))))
         (attack-vector (alist-get (cvss-attack-vector cvss) cvss-attack-vectors))
         (attack-complexity (alist-get (cvss-attack-complexity cvss) cvss-attack-complexities))
         (privileges-required (alist-get (cvss-privileges-required cvss) cvss-privileges))
         (user-interaction (alist-get (cvss-user-interaction cvss) cvss-user-interactions))
         (base-score 0.0)
         (exploitability 0.0))
    (when (listp privileges-required)
      (if (eq (cvss-scope cvss) 'unchanged)
          (setq privileges-required (car privileges-required))
        (setq privileges-required (cadr privileges-required))))
    (setq exploitability (* 8.22 attack-vector attack-complexity
                            privileges-required user-interaction))
    (setq base-score
          (cond ((<= impact 0.0)
                 0.0)
                ((eq (cvss-scope cvss) 'unchanged)
                 (min (+ impact exploitability) 10.0))
                (t
                 (min (* 1.08 (+ impact exploitability)) 10.0))))
    (list (/ (fceiling (* base-score 10)) 10)
          (/ (fround (* exploitability 10)) 10)
          (/ (fround (* impact 10)) 10))))

(defun cvss-vector (cvss)
  "Return a vector string for CVSS."
  (apply #'format
         "CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s"
         (mapcar #'(lambda (s) (upcase (substring (symbol-name s) 0 1)))
                 cvss)))

(defun cvss-severity (cvss)
  "Return the severity for CVSS."
  (let ((base-score (cl-first (cvss-calculate-scores cvss)))
        (severity nil))
    (dolist (sev cvss-severities)
      (when (and (>= base-score (car (cdr sev)))
                 (<= base-score (cadr (cdr sev))))
        (setq severity (car sev))))
    severity))

(defvar cvss-mode-font-lock-keywords
  '(("\\(CVSS\\)\\(:\\)\\(3.[[:digit:]]\\)"
     (1 font-lock-constant-face)
     (2 font-lock-builtin-face)
     (3 font-lock-variable-name-face)
     ("\\(/\\)?\\(AV\\|AC\\|PR\\|UI\\|S\\|C\\|I\\|A\\)\\(:\\)\\([NALPHRUC]\\)"
      nil nil (1 font-lock-comment-face) ; make / disappear as comment
      (2 font-lock-constant-face)
      (3 font-lock-builtin-face)
      (4 font-lock-variable-name-face)))))

(defun cvss-mode-read-cvss ()
  "Read in a CVSS score from the user."
  (make-cvss :attack-vector (intern (completing-read "Attack vector: "
                                                      cvss-attack-vectors))
             :attack-complexity (intern (completing-read "Attack complexity: "
                                                          cvss-attack-complexities))
             :privileges-required (intern (completing-read "Privileges required: "
                                                            cvss-privileges))
             :user-interaction (intern (completing-read "User interaction: "
                                                         cvss-user-interactions))
             :scope (intern (completing-read "Scope: " cvss-scopes))
             :confidentiality-impact (intern (completing-read "Confidentiality impact: "
                                                               cvss-cias))
             :integrity-impact (intern (completing-read "Integrity impact: "
                                                         cvss-cias))
             :availability-impact
             (intern (completing-read "Availability impact: "
                                       cvss-cias))))

(defun cvss-mode-insert-cvss ()
  "Read in a CVSS score from the user and insert it at point."
  (interactive)
  (insert
   (cvss-vector
    (cvss-mode-read-cvss))))

(defun cvss-mode-describe-cvss (cvss)
  "Return a string describing CVSS."
  (let ((scores (cvss-calculate-scores cvss)))
    (apply #'format "%s
      Attack vector: %s
  Attack complexity: %s
Privileges required: %s
   User interaction: %s
              Scope: %s
    Confidentiality: %s
          Integrity: %s
       Availability: %s
         Base Score: %1.1f (%s)"
           (append (list (cvss-vector cvss)) cvss (list (cl-first scores)) (list (cvss-severity cvss))))))

(defun cvss-mode-abbrev-to-symbol (abbrev values)
  "Return the symbol for from VALUES for ABBREV."
  (let ((sym))
    (dolist (value values)
      (when (listp value)
        (setq value (car value)))
      (when (string= abbrev (upcase (substring (symbol-name value) 0 1)))
        (setq sym value)))
    sym))

(defun cvss-mode-parse-vector (vector)
  "Parse VECTOR to a CVSS."
  (let ((attack-vector)
        (attack-complexity)
        (privileges-required)
        (user-interaction)
        (scope)
        (confidentiality-impact)
        (integrity-impact)
        (availability-impact)
        (parts (split-string vector "/")))
    ;; for now just assume need to  have all 8 (+ version = 9)  parts
    (unless (= (length parts) 9)
      (error "Invalid CVSS vector '%s'" vector))
    (dolist (part parts)
      (let ((elements (split-string part ":"))
            (metric)
            (value))
        (unless (= (length elements) 2)
          (error "Invalid CVSS part '%s'" part))
        (setq metric (car elements))
        (setq value (cadr elements))
        (cond ((string= metric "CVSS")
               (unless (or (string= value "3.0")
                           (string= value "3.1"))
                 (error "Unable to parse CVSS version '%s'" value)))
              ((string= metric "AV")
               (setq attack-vector (cvss-mode-abbrev-to-symbol
                                    value cvss-attack-vectors)))
              ((string= metric "AC")
               (setq attack-complexity (cvss-mode-abbrev-to-symbol
                                        value cvss-attack-complexities)))
              ((string= metric "PR")
               (setq privileges-required (cvss-mode-abbrev-to-symbol
                                          value cvss-privileges)))
              ((string= metric "UI")
               (setq user-interaction (cvss-mode-abbrev-to-symbol
                                       value cvss-user-interactions)))
              ((string= metric "S")
               (setq scope (cvss-mode-abbrev-to-symbol
                            value cvss-scopes)))
              ((string= metric "C")
               (setq confidentiality-impact (cvss-mode-abbrev-to-symbol
                                             value cvss-cias)))
              ((string= metric "I")
               (setq integrity-impact (cvss-mode-abbrev-to-symbol
                                       value cvss-cias)))
              ((string= metric "A")
               (setq availability-impact (cvss-mode-abbrev-to-symbol
                                          value cvss-cias)))
              (t (error "Invalid CVSS metric '%s'" metric)))))
    (make-cvss :attack-vector attack-vector
               :attack-complexity attack-complexity
               :privileges-required privileges-required
               :user-interaction user-interaction
               :scope scope
               :confidentiality-impact confidentiality-impact
               :integrity-impact integrity-impact
               :availability-impact availability-impact)))

(defun cvss-mode-bounds-of-cvss-at-point ()
  "Return the start and end points of a CVSS vector at the current point."
  (save-excursion
    (skip-chars-backward "CVSAPRUINLH013:./")
    ;; for now use a loose definition of a CVSS vector string
    (when (looking-at "CVSS:3.[0-1]/[AVPRCUISNLH/:]+")
      (cons (point) (match-end 0)))))

;; thing-at-point support
(put 'cvss 'bounds-of-thing-at-point 'cvss-mode-bounds-of-cvss-at-point)

(defvar-local cvss-mode-orig-eldoc-documentaion-function eldoc-documentation-function)

(defun cvss-mode-eldoc-function ()
  "`eldoc' support for `cvss-mode'."
  (let ((vector (thing-at-point 'cvss)))
    (or (ignore-errors
          (cvss-mode-describe-cvss (cvss-mode-parse-vector vector)))
        (funcall cvss-mode-orig-eldoc-documentaion-function))))

(define-minor-mode cvss-mode
  "Toggle CVSS mode.
Interactively with no argument, this command toggles the mode.
A positive prefix argument enables the mode, any other prefix
argument disables it.  From Lisp, argument omitted or nil enables
the mode, `toggle' toggles the state.

When CVSS mode is enabled, CVSS vector strings are fontified and
extra details are provided via eldoc etc."
  :init-value nil
  :lighter " CVSS"
  :keymap (let ((map (make-sparse-keymap)))
            (define-key map (kbd "C-c #") #'cvss-mode-insert-vector)
            map)
  (if cvss-mode
      (progn
        (font-lock-add-keywords nil cvss-mode-font-lock-keywords t)
        ;; add eldoc support
        (setq cvss-mode-orig-eldoc-documentaion-function eldoc-documentation-function)
        (set (make-local-variable 'eldoc-documentation-function)
             #'cvss-mode-eldoc-function))
    (font-lock-remove-keywords nil cvss-mode-font-lock-keywords)
    (setq eldoc-documentation-function cvss-mode-orig-eldoc-documentaion-function))
  (font-lock-flush))

(provide 'cvss-mode)
;;; cvss-mode.el ends here
