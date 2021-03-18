;;; guile-aws --- Scheme DSL for the AWS APIs
;;; Copyright © 2019, 2020, 2021 Ricardo Wurmus <rekado@elephly.net>
;;;
;;; Guile-AWS is free software: you can redistribute it and/or modify
;;; it under the terms of the GNU General Public License as published
;;; by the Free Software Foundation, either version 3 of the License,
;;; or (at your option) any later version.
;;;
;;; Guile-AWS is distributed in the hope that it will be useful, but
;;; WITHOUT ANY WARRANTY; without even the implied warranty of
;;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
;;; General Public License for more details.
;;;
;;; You should have received a copy of the GNU General Public License
;;; along with this program.  If not, see
;;; <http://www.gnu.org/licenses/>.

(define-module (aws serialize)
  #:use-module (aws base)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-26)
  #:export (serialize-aws-value
            aws-value->scm))

;; See https://docs.aws.amazon.com/AWSEC2/latest/APIReference/Query-Requests.html
(define* (serialize-aws-value thing)
  ;; XXX: I don't know why this is necessary, but it seems to be
  ;; required that the locationName begin with an uppercase letter.
  ;; There is nothing in the specification that would hint at this,
  ;; but testing against the AWS API have revealed this to be the
  ;; case.  This is at least true for "Value" and "Key" of a "Tag"
  ;; value, and for "ResourceType" of a "TagSpecification".
  (define (up string)
    (let ((s (format #false "~a" string)))
      (string-set! s 0 (char-upcase (string-ref s 0)))
      s))
  (define inner
    (lambda (path thing)
      (cond
       ((aws-structure? thing)
        ;; Operate on members
        (let ((provided-members
               (remove (lambda (member)
                         (eq? '__unspecified__ (aws-member-value member)))
                       (aws-structure-members thing))))
          (map (lambda (member)
                 (inner (cons (or (aws-member-location-name member)
                                  (aws-member-name member))
                              path)
                        (aws-member-value member)))
               provided-members)))

       ((aws-shape? thing)
        (cond
         ((aws-shape-primitive? thing)
          (inner path (aws-shape-value thing)))
         (else
          (inner (cons (or (aws-shape-location-name thing)
                           (aws-shape-aws-name thing))
                       path)
                 (aws-shape-value thing)))))

       ((boolean? thing)
        (inner path (or (and thing "true") "false")))

       ((list? thing)
        (map (lambda (item n)
               (inner (cons n path) item))
             thing
             (iota (length thing) 1)))

       (else
        (format #false "~{~a~^.~}=~a"
                (map up (reverse (filter identity path)))
                thing)))))
  (define (flatten lst)
    (match lst
      (() '())
      ((first . rest)
       ((@ (guile) append)
        (flatten first)
        (flatten rest)))
      (_ (list lst))))
  (flatten (inner '() thing)))

(define* (aws-value->scm thing #:optional strip-name?)
  "Transform the potentially nested AWS value THING into an alist,
which can easily be converted to JSON."
  (cond
   ((aws-structure? thing)
    (let ((members
           (filter-map (lambda (member)
                         (match (aws-member-value member)
                           ('__unspecified__ #false)
                           (value
                            `(,(format #false "~a"
                                       (or (aws-member-location-name member)
                                           (aws-member-name member)))
                              .
                              ,(aws-value->scm value)))))
                       (aws-structure-members thing))))
      (if strip-name?
          members
          `((,(format #false "~a" (aws-structure-aws-name thing))
             . ,members)))))
   ((aws-shape? thing)
    (match (aws-shape-value thing)
      ((? list? l)
       (list->vector (map aws-value->scm l)))
      (x x)))
   ;; TODO: what about the primitive "map" type?  That would also
   ;; appear as a pair, wouldn't it?
   ((pair? thing)
    (list->vector (map (cut aws-value->scm <> 'strip-name) thing)))
   ;; Other primitive value, e.g. string or boolean
   (else thing)))
