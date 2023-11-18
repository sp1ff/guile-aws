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

(define-module (aws request)
  #:use-module (aws base)
  #:use-module (aws serialize)
  #:use-module (ice-9 match)
  #:use-module (ice-9 format)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-19)
  #:use-module (srfi srfi-26)
  #:use-module (gcrypt hash)
  #:use-module (gcrypt hmac)
  #:use-module (rnrs bytevectors)
  #:use-module (web client)
  #:use-module ((web response) #:select (response-content-type))
  #:use-module ((web http) #:select (header-writer declare-header!))
  #:use-module (sxml simple)
  #:use-module (json)
  #:export (%aws-default-region
            %aws-access-key
            %aws-secret-access-key

            compute-signature
            hexify
            sign-headers
            make-operation->request))

;;; Commentary:

;;; See: http://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
;;; Make a request to the AWS API and pass request parameters in the
;;; body of the request.  Auth information is provided in an
;;; Authorization header.

;;; Code:

(define %aws-default-region
  (make-parameter (getenv "AWS_DEFAULT_REGION")))

(define %get-aws-default-region
  (lambda ()
    (or (%aws-default-region)
        (getenv "AWS_DEFAULT_REGION")
        "us-west-2")))

(define %aws-access-key
  (make-parameter (getenv "AWS_ACCESS_KEY_ID")))

(define %get-aws-access-key
  (lambda ()
    (or (%aws-access-key)
        (getenv "AWS_ACCESS_KEY_ID")
        (error "No access key available.  Set the AWS_ACCESS_KEY_ID environment variable."))))

(define %aws-secret-access-key
  (make-parameter (getenv "AWS_SECRET_ACCESS_KEY")))

(define %get-aws-secret-access-key
  (lambda ()
    (or (%aws-secret-access-key)
        (getenv "AWS_SECRET_ACCESS_KEY")
        (error "No secret access key available.  Set the AWS_SECRET_ACCESS_KEY environment variable."))))

(define %algorithm "AWS4-HMAC-SHA256")

(define (sign key msg)
  "Sign the string MSG with the secret key KEY (a bytevector) using the SHA256 algorithm."
  (sign-data key (string->utf8 msg) #:algorithm 'sha256))

(define (hexify bv)
  (format #f "~{~2,'0x~}" (bytevector->u8-list bv)))

;; XXX: Guile's default-val-writer corrupts the Authorization header,
;; because it wraps the value of the SignedHeaders field in quotes.
;; This confuses AWS.
(define put-string (@@ (web http) put-string))
(define put-symbol (@@ (web http) put-symbol))
(define put-char (@@ (web http) put-char))
(define write-qstring (@@ (web http) write-qstring))
(define (my-val-writer k val port)
  (if (or (string-index val #\,)
          (string-index val #\"))
      (write-qstring val port)
      (put-string port val)))
(declare-header! "authorization"
                 (@@ (web http) parse-credentials)
                 (@@ (web http) validate-credentials)
                 (lambda (val port)
                   (match val
                     ((scheme . params)
                      (put-symbol port scheme)
                      (put-char port #\space)
                      ((@@ (web http) write-key-value-list) params port my-val-writer)))))


(define (request-query-string operation-name api-version input)
  "Return a request query string."
  (string-join (cons* (format #false "Action=~a" operation-name)
                      (format #false "Version=~a" api-version)
                      (if input
                          (serialize-aws-value input)
                          '()))
               "&"))

(define (input-arguments->scm input)
  "Return the arguments of the INPUT value as an alist.  Drop the
operation name."
  (match (aws-value->scm input)
    (((op-name . params)) params)))

(define (request-json-string input)
  "Return a request JSON block.  Drop the operation name as it is
already mentioned in the request headers."
  (scm->json-string (input-arguments->scm input)))

(define (request-xml-string xmlns input)
  "Return a request payload in XML format.  Include the URI of the XML
namespace provided in the alist XMLNS."
  (let* ((tree (aws-value->sxml input))
         (tree-with-ns
          (match tree
            (((first . rest))
             (let ((ns-uri
                    (and=> xmlns (lambda (ns)
                                   (assoc-ref ns "uri")))))
               (if ns-uri
                   (list (cons* first `(@ (xmlns ,ns-uri)) rest))
                   tree))))))
    (call-with-output-string
      (lambda (port)
        (sxml->xml tree-with-ns port)))))

(define (parameterize-request-uri request-format-string input)
  "Process the format string URL in REQUEST-FORMAT-STRING and replace
all placeholders (strings surrounded by curly braces) with their
corresponding value in INPUT."
  (let ((arguments (input-arguments->scm input))
        (parts (string-split request-format-string (char-set #\{ #\}))))
    ;; Every second item corresponds to a placeholder.
    (string-join (map (lambda (part index)
                        (if (odd? index)
                            (or (assoc-ref arguments part)
                                (error (format #false
                                               "Cannot parameterize URL `~a'; missing value `~a'~%"
                                               request-format-string part)))
                            part))
                      parts
                      (iota (length parts)))
                 "")))

(define* (compute-signature string-to-sign
                            #:key
                            (aws-secret-key (%get-aws-secret-access-key))
                            (aws-region (%get-aws-default-region))
                            aws-service-name)
  "Compute the AWS signature over STRING-TO-SIGN with the provided
SECRET-KEY, and for the given AWS-SERVICE-NAME.  All arguments are
strings."
  (unless aws-secret-key
    (error "No secret access key available.  Set the AWS_SECRET_ACCESS_KEY environment variable."))
  (let* ((now         (current-date 0))
         (date-stamp  (date->string now "~Y~m~d"))
         (kdate       (sign (string->utf8
                             (string-append "AWS4" aws-secret-key))
                            date-stamp))
         (kregion     (sign kdate aws-region))
         (kservice    (sign kregion aws-service-name))
         (signing-key (sign kservice "aws4_request")))
    (hexify (sign signing-key string-to-sign))))

(define (credential-scope date-stamp region service-name)
  (string-join (list date-stamp
                     region
                     service-name
                     "aws4_request") "/"))

(define* (sign-headers headers
                       #:key
                       (method "GET")
                       (canonical-querystring "")
                       canonical-uri
                       payload-hash
                       service-name
                       (region (%get-aws-default-region))
                       (secret-key (%get-aws-secret-access-key))
                       (access-key (%get-aws-access-key)))
  "Given a bunch of headers as an alist, return a new alist of headers
that includes the authorization and x-amz-date headers.  This can be
used for presigned URLs."
  (unless secret-key
    (error "No secret access key available.  Set the AWS_SECRET_ACCESS_KEY environment variable."))
  (unless access-key
    (error "No access key available.  Set the AWS_ACCESS_KEY_ID environment variable."))
  (unless service-name
    (error "Must provide service-name."))
  (let* ((now (current-date 0))
         (amz-date (date->string now "~Y~m~dT~H~M~SZ"))
         (date-stamp (date->string now "~Y~m~d"))
         (headers
          (sort (cons `(x-amz-date . ,amz-date)
                      headers)
                (lambda (a b)
                  (string< (symbol->string (first a))
                           (symbol->string (first b))))))
         (canonical-headers
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
         (canonical-request
          (string-join (list method
                             canonical-uri
                             canonical-querystring
                             canonical-headers
                             signed-headers
                             payload-hash)
                       "\n"))
         (scope
          (credential-scope date-stamp
                            region
                            service-name))
         (string-to-sign
          (string-join (list %algorithm
                             amz-date
                             scope
                             (hexify (sha256 (string->utf8 canonical-request))))
                       "\n"))
         (signature
          (compute-signature string-to-sign
                             #:aws-secret-key secret-key
                             #:aws-region region
                             #:aws-service-name service-name)))

    ;; For DynamoDB, the request can include any headers, but MUST
    ;; include "host", "x-amz-date", "x-amz-target", "content-type",
    ;; and "Authorization".  Except for the authorization header, the
    ;; headers must be included in the canonical-headers and
    ;; signed-headers values, as noted earlier.  Order here is not
    ;; significant.
    (cons `(authorization . (,(string->symbol %algorithm)
                             (Credential . ,(string-append access-key "/" scope))
                             (SignedHeaders . ,signed-headers)
                             (Signature . ,signature)))
          (filter cdr headers))))

(define* (make-operation->request api-metadata)
  "Return a procedure that accepts an operation and returns an HTTP request."
  (define endpoint-prefix
    (assoc-ref api-metadata 'endpointPrefix))
  (define service-name endpoint-prefix)
  (define api-version
    (assoc-ref api-metadata 'apiVersion))

  (lambda* (#:key
            http operation-name
            xml-namespace
            input)
    (define region (%get-aws-default-region))
    (define access-key (%get-aws-access-key))
    (define method
      (assoc-ref http "method"))
    (define host
            (or (assoc-ref api-metadata 'globalEndpoint)
                (string-join (list endpoint-prefix
                                   region
                                   "amazonaws.com")
                             ".")))

    (define endpoint
      (or (getenv "GUILE_AWS_DEBUG_ENDPOINT")
          (string-append "https://" host)))
    (define json?
      (match (assoc-ref api-metadata 'protocol)
        ((or "json" "rest-json") #true)
        (_ #false)))
    (define content-type
      (if json?
          `(,(string->symbol
              (string-append "application/x-amz-json-"
                             (or (assoc-ref api-metadata 'jsonVersion)
                                 "1.0")))
            (charset . "utf-8"))
          '(application/x-www-form-urlencoded (charset . "utf-8"))))

    ;; DynamoDB (and possibly other JSON APIs) needs this, query
    ;; string APIs do not.
    (define amz-target (and=> (assoc-ref api-metadata 'targetPrefix)
                              (cut string-append <> "."
                                   operation-name)))

    (define request-parameters
      (match (assoc-ref api-metadata 'protocol)
        ((or "json"
             "rest-json")
         (request-json-string input))
        ("rest-xml"
         (request-xml-string xml-namespace input))
        (_
         (request-query-string operation-name api-version input))))

    (define payload-hash
      (hexify (sha256 (string->utf8 request-parameters))))

    ;; https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
    (define uri
      (or (and=> (assoc-ref http "requestUri")
                 (lambda (format-string)
                   (parameterize-request-uri format-string input)))
          "/"))

    (define uri-components (string-split uri #\?))
    (define canonical-uri (list-ref uri-components 0))
    (define canonical-querystring
      (if (> (length uri-components) 1)
          (list-ref uri-components 1)
          ""))

    (define headers
      (filter cdr `((content-type . ,content-type)
                    (host         . (,host . #f))
                    (x-amz-content-sha256 . ,payload-hash)
                    (x-amz-target . ,amz-target))))
    (define signed-headers
      (sign-headers headers
                    #:access-key access-key
                    #:method method
                    #:region region
                    #:service-name service-name
                    #:canonical-uri canonical-uri
                    #:canonical-querystring canonical-querystring
                    #:payload-hash payload-hash))

    (call-with-values
        (lambda ()
          (http-request (string-append endpoint uri)
                        #:method (string->symbol method)
                        #:body (string->utf8 request-parameters)
                        #:headers signed-headers))
      (lambda (response body)
        (let ((server-text (match body
                             ((? bytevector? bv)
                              (utf8->string bv))
                             ((? string? s) s)
                             (anything anything))))
          (match (response-content-type response)
            ((or ('application/x-amz-json-1.1 . rest)
                 ('application/json . rest))
             (or (and=> server-text json-string->scm)
                 #true))
            ((or ('application/xml . rest) ('text/xml . rest))
             (or (and=> server-text xml->sxml)
                 #true))
            (_ server-text)))))))
