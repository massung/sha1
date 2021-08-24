(defpackage :sha1-asd
  (:use :cl :asdf))

(in-package :sha1-asd)

(defsystem :sha1
  :name "sha1"
  :version "1.0"
  :author "Jeffrey Massung"
  :license "Apache 2.0"
  :description "SHA1 Digest and HMAC for Common Lisp."
  :serial t
  :components ((:file "sha1")))
