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
(define* (serialize-aws-value thing #:key (path '()) n (depth 0))
  (define top? (zero? depth))
  (cond
   ((aws-structure? thing)
    (filter-map (lambda (member)
                  (match (aws-member-value member)
                    ('__unspecified__ #f)
                    (value
                     (serialize-aws-value value
                                          #:path
                                          (if top?
                                              (list (or (aws-member-location-name member)
                                                        (aws-member-name member)))
                                              (cons* (or (aws-member-location-name member)
                                                         (aws-member-name member))
                                                     n
                                                     (aws-structure-aws-name thing)
                                                     path))
                                          #:depth
                                          (1+ depth)))))
                (aws-structure-members thing)))
   ((aws-shape? thing)
    (cond
     ((aws-shape-primitive? thing)
      (serialize-aws-value (aws-shape-value thing)
                           #:path path
                           #:depth (1+ depth)))
     (else
      (serialize-aws-value (aws-shape-value thing)
                           #:path
                           (cons (or (aws-shape-location-name thing)
                                     (aws-shape-aws-name thing)) path)
                           #:depth (1+ depth)))))
   ((boolean? thing)
    (serialize-aws-value (or (and thing "true") "false")
                         #:path path
                         #:depth (1+ depth)))
   ((list? thing)
    (apply append
           (map (lambda (item n)
                  (serialize-aws-value item
                                       #:path path
                                       #:n n
                                       #:depth (1+ depth)))
                thing
                (iota (length thing) 1))))
   (else
    (format #f "~a=~a"
            (string-join (map (cut format #f "~a" <>)
                              (reverse (filter identity path)))
                         ".")
            thing))))

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
