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

(define-module (language aws spec)
  #:use-module (aws base)
  #:use-module (aws utils json)
  #:use-module (ice-9 match)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-2)
  #:use-module (system base language)
  #:export (aws))

(define %shape-specs (list))

(define (primitive? exp)
  (member (assoc-ref exp "type")
          '("string"
            "blob"
            "boolean"
            "timestamp"
            "integer" "long"
            "double" "float"
            "list")))

(define (primitive-type-checker exp)
  "Return an S-expression representation of a type checking procedure
for a shape expression EXP with a primitive data type.  Throw an error
if this is not a primitive data type."
  (match (assoc-ref exp "type")
    ("string"
     (let ((enum (and=> (assoc-ref exp "enum")
                        vector->list))
           (min (assoc-ref exp "min"))
           (max (assoc-ref exp "max")))
       `(lambda (value)
          (and (string? value)
               ,(if enum
                    `(member value ',enum)
                    #true)
               ,(if (or min max)
                    `(let ((len (string-length value)))
                       (and ,(if min `(>= len ,min) #true)
                            ,(if max `(<= len ,max) #true)))
                    #true)))))
    ("blob" 'bytevector?)
    ("boolean" 'boolean?)
    ("timestamp" 'date?)
    ((or "integer" "long")
     `(lambda (value)
        (let ((min ,(assoc-ref exp "min"))
              (max ,(assoc-ref exp "max")))
          (and (integer? value)
               (if min (>= value min) #t)
               (if max (<= value max) #t)))))
    ((or "double" "float") 'real?)
    ("list"
     (let ((member-spec (assoc-ref exp "member")))
       (if member-spec
           (let ((shape-name (string->symbol (assoc-ref member-spec "shape"))))
             `(lambda (value)
                (let ((shape ',shape-name))
                  (and (list? value)
                       ;; Use the primitive type checker here as well
                       ;; in case the member spec is a wrapper around
                       ;; a primitive value.
                       (every ,(let ((target-spec (assoc-ref %shape-specs shape-name)))
                                 (if (and=> target-spec primitive?)
                                     ;; Apply the primitive type check
                                     ;; directly.  This allows us to
                                     ;; avoid unnecessary wrapping.
                                     (primitive-type-checker target-spec)
                                     ;; Otherwise make sure the value has the correct type
                                     '(lambda (item)
                                        (and=> (aws-name item)
                                               (cut eq? <> shape)))))
                              value)))))
           'list?)))
    ("map"
     `(lambda (value)
        (let ((key-shape
               ',(string->symbol (assoc-ref (assoc-ref exp "key") "shape")))
              (value-shape
               ',(string->symbol (assoc-ref (assoc-ref exp "value") "shape"))))
          (and (list? value)
               (every (match-lambda
                        ((key . value)
                         (and (and=> (aws-name key)
                                     (cut eq? <> key-shape))
                              (and=> (aws-name value)
                                     (cut eq? <> value-shape))))
                        (_ #f))
                      value)))))
    ;; Not a primitive type.
    (unknown
     (error (format #f "unknown primitive type: ~a~%" unknown)))))

(define (compile-member-args members required)
  (append-map (match-lambda
                ((name . spec)
                 (let ((slot-name (string->symbol name)))
                   (if (member name required)
                       `((,slot-name
                          (error (format #f "~a: required value missing."
                                         ,name))))
                       (list (list slot-name ''__unspecified__))))))
              members))

(define (compile-shape-stubs exp)
  "Compile an AWS shape expression EXP to a stub."
  (match exp
    ((name . spec)
     ;; Record shape spec for later type checking
     (set! %shape-specs
           (acons (string->symbol name)
                  (alist-delete "documentation" spec)
                  %shape-specs))
     `(define ,(string->symbol name) #f))))

(define (compile-shape exp)
  "Compile an AWS shape expression EXP."
  (define required
    (or (and=> (assoc-ref exp "required") vector->list)
        '()))
  (define members (assoc-ref exp "members"))
  (define structure? (string=? (assoc-ref exp "type") "structure"))
  (match exp
    ((name . spec)
     (let ((scm-name (string->symbol name)))
       (if structure?
           `(begin
              (define ,scm-name
                (lambda* (#:key ,@(compile-member-args members required))
                  ,(assoc-ref spec "documentation")
                  ;; Type checks
                  ,@(map (match-lambda
                           ((name . spec)
                            (let* ((key-name (string->symbol name))
                                   (target-shape (string->symbol (assoc-ref spec "shape")))
                                   (target-spec (assoc-ref %shape-specs target-shape)))
                              `(unless (eq? ,key-name '__unspecified__)
                                 ,(if (and=> target-spec primitive?)
                                      ;; Apply the primitive type
                                      ;; check directly.  This allows
                                      ;; us to avoid unnecessary
                                      ;; wrapping.
                                      `(,(primitive-type-checker target-spec) ,key-name)
                                      ;; Otherwise make sure the value has the correct type
                                      `(ensure ,key-name
                                               ',(string->symbol (assoc-ref spec "shape"))))))))
                         members)
                  (aws-structure
                   ',scm-name
                   (list ,@(map (match-lambda
                                  ((name . spec)
                                   `(aws-member #:name ',(string->symbol name)
                                                #:shape ',(and=> (assoc-ref spec "shape") string->symbol)
                                                #:location ,(assoc-ref spec "location")
                                                #:location-name ,(assoc-ref spec "locationName")
                                                #:documentation ,(assoc-ref spec "documentation")
                                                #:value ,(string->symbol name))))
                                members)))))
              (export ,scm-name))
           `(begin
              (define ,scm-name
                (aws-shape #:aws-name ',scm-name
                           #:primitive?
                           ,(and (primitive?
                                  (alist-delete "documentation" spec)) #t)
                           #:type-checker
                           ,(primitive-type-checker
                             (alist-delete "documentation" spec))
                           #:location
                           ',(and=> (assoc-ref spec "location") string->symbol)
                           #:location-name
                           ,(assoc-ref spec "locationName")
                           #:documentation
                           ,(assoc-ref spec "documentation")))
              (export ,scm-name)))))))

(define (compile-operation exp)
  "Compile an AWS operation expression EXP."
  (match exp
    ((name . spec)
     `(begin
        (define ,(string->symbol name)
          (aws-operation
           operation->request
           #:name ,name
           #:input-constructor
           ,(and=> (assoc-ref spec "input")
                   (lambda (input)
                     (and=> (assoc-ref input "shape") string->symbol)))
           #:input-type
           ',(and=> (assoc-ref spec "input")
                    (lambda (input)
                      (and=> (assoc-ref input "shape") string->symbol)))
           #:output-type
           ',(and=> (assoc-ref spec "output")
                   (lambda (output)
                     (and=> (assoc-ref output "shape") string->symbol)))
           #:http
           ;; This includes things like "method", "requestUri", and "responseCode"
           ',(assoc-ref spec "http")
           #:documentation
           ,(assoc-ref spec "documentation")))
        (export ,(string->symbol name))))))

(define (compile-scheme exp env opts)
  (and-let* ((meta (assoc-ref exp "metadata"))
             (module-name (string->symbol (assoc-ref meta "uid"))))
    (values `(begin
               (define-module (aws api ,module-name)
                 #:use-module (aws base)
                 #:use-module (aws request)
                 #:use-module (ice-9 match)
                 #:use-module (srfi srfi-1)
                 #:use-module (srfi srfi-9)
                 #:use-module ((srfi srfi-19) #:select (date?))
                 #:use-module (srfi srfi-26)
                 #:use-module ((rnrs bytevectors) #:select (bytevector?)))
               (define-public api-documentation
                 ,(assoc-ref exp "documentation"))
               (define api-metadata
                 ',(map (lambda (key)
                          `(,(string->symbol key) . ,(assoc-ref meta key)))
                        (map car meta)))
               (define operation->request
                 (make-operation->request api-metadata))
               ;; Define all shapes first so that we don't have to do
               ;; a topological sort.  In the next step the shapes are
               ;; redefined.
               ,@(map compile-shape-stubs (assoc-ref exp "shapes"))
               ,@(map compile-shape (assoc-ref exp "shapes"))
               ,@(map compile-operation (assoc-ref exp "operations")))
            env env)))

(define-language aws
  #:title "AWS JSON specification language"
  #:reader (lambda (port env)
             (if (eof-object? (peek-char port))
                 (read-char port)
                 (read-json port)))
  #:compilers `((scheme . ,compile-scheme))
  #:printer write)
