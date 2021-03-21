;;; guile-aws --- Scheme DSL for the AWS APIs
;;; Copyright © 2019-2021 Ricardo Wurmus <rekado@elephly.net>
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

;;; Run the following command to enter a development environment for
;;; Guile AWS
;;;
;;;  $ guix environment -l .guix.scm

(use-modules ((guix licenses) #:prefix license:)
             (guix packages)
             (guix utils)
             (guix build-system gnu)
             (gnu packages)
             (gnu packages autotools)
             (gnu packages gnupg)
             (gnu packages guile)
             (gnu packages guile-xyz)
             (gnu packages graphviz)
             (gnu packages pkg-config))

(define guile-aws
  (package
    (name "guile-aws")
    (version "dev")
    (source #false)
    (build-system gnu-build-system)
    (native-inputs
     `(("autoconf" ,autoconf)
       ("automake" ,automake)
       ("pkg-config" ,pkg-config)))
    (inputs
     `(("guile" ,guile-3.0)))
    (propagated-inputs
     `(("guile-json" ,guile-json-3)
       ("guile-gcrypt" ,guile-gcrypt)))
    (home-page "https://git.elephly.net/software/guile-aws.git")
    (synopsis "AWS client for Guile")
    (description "Guile AWS is pre-alpha software.  At the very
least it’s yet another demonstration that Guile’s compiler tower can
be used to generate an embedded domain specific language from JSON
specifications.")
    (license license:gpl3+)))

guile-aws
