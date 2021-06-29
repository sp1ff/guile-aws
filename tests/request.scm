;;; guile-aws --- Scheme DSL for the AWS APIs
;;; Copyright © 2021 Ricardo Wurmus <rekado@elephly.net>
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

(define-module (test-request)
  #:use-module (aws request)
  #:use-module (aws api ec2-2016-11-15)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-64))

(test-begin "request")

(test-assert "sign-headers: adds x-amz-date and authorization headers"
  (let* ((headers
          (filter cdr `((content-type . (application/x-www-form-urlencoded
                                         (charset . "utf-8")))
                        (host         . ("http://localhost" . #f))
                        (x-amz-target . #false))))
         (signed (sign-headers headers
                               #:canonical-uri ""
                               #:service-name "s3"
                               #:payload-hash "abcdefg"
                               #:secret-key "SECRET_ABCDEFG"
                               #:access-key "ACCESS_ABCDEFG")))
    (and (assoc-ref signed 'x-amz-date)
         (assoc-ref signed 'authorization))))

(test-end "request")
