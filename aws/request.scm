;;; guile-aws --- Scheme DSL for the AWS APIs
;;; Copyright © 2019, 2020 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (aws request)
  #:use-module (aws base)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-19)
  #:use-module (srfi srfi-26)
  #:use-module (gcrypt hash)
  #:use-module (gcrypt hmac)
  #:use-module (rnrs bytevectors)
  #:use-module (web client)
  #:use-module ((web http) #:select (header-writer))
  #:use-module (sxml simple)
  #:export (make-operation->request serialize-aws-value))

;;; Commentary:

;;; See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
;;; Make a POST request and pass request parameters in the body of the
;;; request.  Auth information is provided in an Authorization header.

;;; Code:

(define algorithm "AWS4-HMAC-SHA256")

(define (sign key msg)
  "Sign the string MSG with the secret key KEY (a bytevector) using the SHA256 algorithm."
  (sign-data key (string->utf8 msg) #:algorithm 'sha256))

(define (hexify bv)
  (format #f "~{~2,'0x~}" (bytevector->u8-list bv)))

;; XXX: Guile's default-val-writer corrupts the Authorization header,
;; because it wraps the value of the SignedHeaders field in quotes.
;; This confuses AWS.
(define (my-default-val-writer k val port)
  (if (or (string-index val #\,)
          (string-index val #\"))
      ((@@ (web http) write-qstring) val port)
      ((@@ (web http) put-string) port val)))
(module-set!
 (resolve-module '(web http))
 'default-val-writer my-default-val-writer)


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
    (append-map (lambda (item n)
                  (serialize-aws-value item
                                       #:path path
                                       #:n n
                                       #:depth (1+ depth)))
                thing
                (iota (length thing) 1)))
   (else (format #f "~a=~a"
                 (string-join (map (cut format #f "~a" <>)
                                   (reverse (filter identity path)))
                              ".")
                 thing))))

(define* (make-operation->request api-metadata)
  "Return a procedure that accepts an operation and returns an HTTP request."
  (define endpoint-prefix
    (assoc-ref api-metadata 'endpointPrefix))
  (define service-name endpoint-prefix)
  (define api-version
    (assoc-ref api-metadata 'apiVersion))

  (lambda* (#:key http operation-name input)
    (define region
      (or (getenv "AWS_DEFAULT_REGION")
          "us-west-2"))
    (define access-key
      (or (getenv "AWS_ACCESS_KEY_ID")
          (error "No access key available.  Set the AWS_ACCESS_KEY_ID environment variable.")))
    (define secret-key
      (or (getenv "AWS_SECRET_ACCESS_KEY")
          (error "No secret access key available.  Set the AWS_SECRET_ACCESS_KEY environment variable.")))
    (define method
      (assoc-ref http "method"))
    (define host
      (string-join (list endpoint-prefix
                         region
                         "amazonaws.com")
                   "."))
    (define endpoint
      (string-append "https://" host "/"))
    (define content-type
      '(application/x-www-form-urlencoded (charset . "utf-8")))

    ;; DynamoDB needs this, others don't.
    (define amz-target (and=> (assoc-ref api-metadata 'targetPrefix)
                              (cut string-append <> "."
                                   operation-name)))

    ;; TODO: some APIs use JSON, others (like EC2) use plain query strings.
    (define request-parameters
      (string-join (cons* (format #f "Action=~a" operation-name)
                          (format #f "Version=~a" api-version)
                          (if input
                              (serialize-aws-value input)
                              '()))
                   "&"))

    (define payload-hash
      (hexify (sha256 (string->utf8 request-parameters))))

    (define now (current-date 0))
    (define amz-date
      (date->string now "~Y~m~dT~H~M~SZ"))
    (define date-stamp
      (date->string now "~Y~m~d"))

    
    ;; https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

    ;; TODO: Create canonical URI--the part of the URI from domain to query
    ;; string (use '/' if no path)
    (define canonical-uri "/")

    (define headers
      (filter cdr `((content-type . ,content-type)
                    (host         . (,host . #f))
                    (x-amz-date   . ,amz-date)
                    (x-amz-target . ,amz-target))))
    (define authorization-header
      (let* ((canonical-headers
              ;; Header names must be trimmed, lower-case, sorted in
              ;; code point order from low to high!  Note: there must
              ;; be a trailing newline character.
              (string-join (map (match-lambda
                                  ((key . value)
                                   (string-append (symbol->string key) ":"
                                                  (with-output-to-string
                                                    (lambda ()
                                                      ((header-writer key) value (current-output-port)))))))
                                headers)
                           "\n" 'suffix))
             (signed-headers
              ;; This lists the headers in the canonical-headers list,
              ;; delimited with ";" and in alpha order.  The request
              ;; can include any headers; canonical-headers and
              ;; signed-headers include those that you want to be
              ;; included in the hash of the request. "Host" and
              ;; "x-amz-date" are always required.
              (string-join (map (compose symbol->string first) headers) ";"))
             ;; The query string is blank because parameters are passed
             ;; in the body of the request.
             (canonical-querystring "")
             (canonical-request
              (string-join (list method
                                 canonical-uri
                                 canonical-querystring
                                 canonical-headers
                                 signed-headers
                                 payload-hash)
                           "\n"))
             (credential-scope
              (string-join (list date-stamp
                                 region
                                 service-name
                                 "aws4_request") "/"))
             (string-to-sign
              (string-join (list algorithm
                                 amz-date
                                 credential-scope
                                 (hexify (sha256 (string->utf8 canonical-request))))
                           "\n"))
             (signature
              (let* ((kdate       (sign (string->utf8 (string-append "AWS4" secret-key)) date-stamp))
                     (kregion     (sign kdate region))
                     (kservice    (sign kregion service-name))
                     (signing-key (sign kservice "aws4_request")))
                (hexify (sign signing-key string-to-sign)))))
        `(,(string->symbol algorithm)
          (Credential . ,(string-append access-key "/" credential-scope))
          (SignedHeaders . ,signed-headers)
          (Signature . ,signature))))

    ;; For DynamoDB, the request can include any headers, but MUST
    ;; include "host", "x-amz-date", "x-amz-target", "content-type",
    ;; and "Authorization".  Except for the authorization header, the
    ;; headers must be included in the canonical-headers and
    ;; signed-headers values, as noted earlier.  Order here is not
    ;; significant.
    (define new-headers
      (cons `(Authorization . ,authorization-header)
            (filter cdr headers)))

    (call-with-values
        (lambda ()
          (http-post endpoint
                     ;#:method (string->symbol method)
                        #:body (string->utf8 request-parameters)
                        #:headers new-headers))
      (lambda (response body)
        (xml->sxml (match body
                     ((? bytevector? bv)
                      (utf8->string bv))
                     ((? string? s) s)))))))
