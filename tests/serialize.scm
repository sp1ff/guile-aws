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

(define-module (test-serialize)
  #:use-module (aws serialize)
  #:use-module (aws api ec2-2016-11-15)
  #:use-module (srfi srfi-1)
  #:use-module (srfi srfi-64))

(test-begin "serialize")

(define-syntax-rule (mock (module proc replacement) body ...)
  "Within BODY, replace the definition of PROC from MODULE with the definition
given by REPLACEMENT."
  (let* ((m (resolve-module 'module))
         (original (module-ref m 'proc)))
    (dynamic-wind
      (lambda () (module-set! m 'proc replacement))
      (lambda () body ...)
      (lambda () (module-set! m 'proc original)))))

(test-equal "simple query serialization"
  '("ImageId=ami-72aa081b" "MaxCount=1" "MinCount=1")
  (serialize-aws-value (RunInstancesRequest
                        #:ImageId "ami-72aa081b"
                        #:MinCount 1
                        #:MaxCount 1)))

(test-equal "simple query serialization with lists"
  '("ImageId=ami-72aa081b" "MaxCount=1" "MinCount=1"
    "SecurityGroupId.1=sg-a"
    "SecurityGroupId.2=sg-b"
    "SecurityGroupId.3=sg-c")
  (serialize-aws-value (RunInstancesRequest
                        #:ImageId "ami-72aa081b"
                        #:MinCount 1
                        #:MaxCount 1
                        #:SecurityGroupIds
                        (list "sg-a" "sg-b" "sg-c"))))

(test-equal "simple query serialization with nested structures"
  '("ImageId=ami-72aa081b" "MaxCount=1" "MinCount=1"
    "TagSpecification.1.ResourceType=instance"
    "TagSpecification.1.Tag.1.Key=project"
    "TagSpecification.1.Tag.1.Value=pigx-web"
    "TagSpecification.1.Tag.2.Key=pigx-web:resource"
    "TagSpecification.1.Tag.2.Value=user-vm"
    "TagSpecification.1.Tag.3.Key=pigx-web:username"
    "TagSpecification.1.Tag.3.Value=username"
    "TagSpecification.1.Tag.4.Key=pigx-web:project"
    "TagSpecification.1.Tag.4.Value=project")
  (serialize-aws-value (RunInstancesRequest
                        #:ImageId "ami-72aa081b"
                        #:MinCount 1
                        #:MaxCount 1
                        #:TagSpecifications
                        (list (TagSpecification
                               #:ResourceType "instance"
                               #:Tags (list (Tag #:Key "project"
                                                 #:Value "pigx-web")
                                            (Tag #:Key "pigx-web:resource"
                                                 #:Value "user-vm")
                                            (Tag #:Key "pigx-web:username"
                                                 #:Value "username")
                                            (Tag #:Key "pigx-web:project"
                                                 #:Value "project")))))))

;; TODO: awscli encodes things differently.  They use uppercase names
;; for the tags ("Key" and "Value" instead of "key" and "value" as
;; specified in the locationName property).

;; TODO: also test that colon is URL encoded.

(test-end "serialize")
