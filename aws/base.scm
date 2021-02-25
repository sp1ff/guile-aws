;;; guile-aws --- Scheme DSL for the AWS APIs
;;; Copyright © 2019 Ricardo Wurmus <rekado@elephly.net>
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

;;; Commentary:
;;;
;;; This module defines the basic record types, their constructors and
;;; accessors, as well as the type checker procedure generator.
;;;
;;; There are three records: 1) <aws-shape> for types that are little
;;; more than type-checked wrappers around primitive types (e.g. a
;;; ranged integer, a typed list, or a string with an enumeration of
;;; possible values; 2) <aws-structure> for composite types, which can
;;; have an arbitrary number of members of different types; and 3)
;;; <aws-operation>, which is how either of the previous types can be
;;; turned into API requests.
;;;
;;; Code:

(define-module (aws base)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-9)
  #:use-module (srfi srfi-9 gnu)
  #:use-module ((srfi srfi-19) #:select (date?))
  #:use-module (srfi srfi-26)
  #:use-module ((rnrs bytevectors) #:select (bytevector?))
  #:export (aws-shape
            aws-shape?
            aws-shape-aws-name
            aws-shape-value
            aws-shape-location-name
            aws-shape-primitive?

            aws-structure
            aws-structure-aws-name
            aws-structure-members
            aws-structure?

            aws-member
            aws-member-name
            aws-member-value
            aws-member-documentation
            aws-member-location
            aws-member-location-name

            aws-name
            ensure

            aws-operation))


;;; Simple shapes

(define-record-type <aws-shape>
  (make-aws-shape aws-name primitive? type-checker location location-name value)
  aws-shape?
  (aws-name      aws-shape-aws-name)
  (primitive?    aws-shape-primitive?)
  (type-checker  aws-shape-type-checker)
  (location      aws-shape-location)
  (location-name aws-shape-location-name)
  (value         aws-shape-value))

(define* (aws-shape #:key aws-name primitive? type-checker location location-name documentation)
  (let ((proc (lambda (value)
                (if (type-checker value)
                    (make-aws-shape aws-name primitive? type-checker location location-name value)
                    (error (format #f "~a: invalid value: ~a~%"
                                   aws-name value))))))
    (set-procedure-property! proc 'name aws-name)
    (set-procedure-property! proc 'documentation documentation)
    proc))

(set-record-type-printer! <aws-shape>
                          (lambda (obj port)
                            (format port "#<aws:~a ~a>"
                                    (aws-shape-aws-name obj)
                                    (aws-shape-value obj))))


;;; Structures
(define-record-type <aws-structure>
  (aws-structure aws-name members)
  aws-structure?
  (aws-name       aws-structure-aws-name)
  (members        aws-structure-members))

(set-record-type-printer! <aws-structure>
                          (lambda (obj port)
                            (format port "#<aws-structure:~a>"
                                    (aws-structure-aws-name obj))))

(define-record-type <aws-member>
  (make-aws-member name value shape documentation location location-name)
  aws-member?
  (name           aws-member-name)
  (value          aws-member-value)
  (shape          aws-member-shape)
  (documentation  aws-member-documentation)
  (location       aws-member-location)
  (location-name  aws-member-location-name))

(define* (aws-member #:key name value shape documentation location location-name)
  (make-aws-member name value shape documentation location location-name))

(set-record-type-printer! <aws-structure>
                          (lambda (obj port)
                            (format port "#<aws-structure:~a>"
                                    (aws-structure-aws-name obj))))


(define (aws-name thing)
  (cond
   ((aws-structure? thing)
    (aws-structure-aws-name thing))
   ((aws-shape? thing)
    (aws-shape-aws-name thing))
   (else #f)))

(define (ensure value type)
  (unless (and=> (aws-name value) (cut eq? <> type))
    (error (format #f "wrong type: ~a, expected ~a~%."
                   value type))))


(define* (aws-operation requester #:key name input-type output-type http documentation)
  (let ((proc
         (lambda* (#:optional input)
           (unless (eq? (aws-name input) input-type)
             (error (format #f "~a: input must be of type ~a: ~a~%"
                            name input-type input)))
           ;; TODO: do something with the response!
           (requester #:http http #:operation-name name #:input input))))
    (set-procedure-property! proc 'documentation documentation)
    (set-procedure-property! proc 'name name)
    proc))
