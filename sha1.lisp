;;;; SHA1 Digest and HMAC for Common Lisp
;;;;
;;;; Copyright (c) Jeffrey Massung
;;;;
;;;; This file is provided to you under the Apache License,
;;;; Version 2.0 (the "License"); you may not use this file
;;;; except in compliance with the License.  You may obtain
;;;; a copy of the License at
;;;;
;;;;    http://www.apache.org/licenses/LICENSE-2.0
;;;;
;;;; Unless required by applicable law or agreed to in writing,
;;;; software distributed under the License is distributed on an
;;;; "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
;;;; KIND, either express or implied.  See the License for the
;;;; specific language governing permissions and limitations
;;;; under the License.
;;;;

(defpackage :sha1
  (:use :cl)
  (:export
   #:sha1-digest
   #:sha1-hex
   #:sha1-base64

   ;; HMAC functions
   #:hmac-sha1-digest
   #:hmac-sha1-hex
   #:hmac-sha1-base64))

(in-package :sha1)

;;; ----------------------------------------------------

(deftype function-designator ()
  '(or function symbol))

(defvar *base64-encoder* nil
  "SHA1-BASE64 and HMAC-SHA1-BASE64 use this function if no encoder is provided.")

;;; ----------------------------------------------------

(defun word (v chunk byte)
  "Read a 32-bit, big-endian word from a message chunk."
  (logior (ash (aref v (+ chunk byte 0)) 24)
          (ash (aref v (+ chunk byte 1)) 16)
          (ash (aref v (+ chunk byte 2)) 8)
          (ash (aref v (+ chunk byte 3)) 0)))

;;; ----------------------------------------------------

(defun rotate-word (w &optional (bits 1))
  "Rotate a 32-bit word left by bits."
  (logior (logand (ash w (- bits 32)) (1- (ash 1 bits)))
          (logand (ash w bits) #xffffffff)))

;;; ----------------------------------------------------

(defun hash-digest (hh)
  "Convert a 160-bit hash to a 20-byte digest list."
  (loop for i from 152 downto 0 by 8 collect (logand (ash hh (- i)) #xff)))

;;; ----------------------------------------------------

(defun hash-vector (seq)
  "Convert x to an unsigned-byte vector."
  (if (not (stringp seq))
      seq
    (map '(vector (unsigned-byte 8)) #'char-code seq)))

;;; ----------------------------------------------------

(defun digest (seq)
  "Create a SHA-1 digest from an adjustable vector containing the message."
  (let* ((h0 #x67452301)
         (h1 #xefcdab89)
         (h2 #x98badcfe)
         (h3 #x10325476)
         (h4 #xc3d2e1f0)

         ;; convert the sequence into an adjustable vector
         (v (make-array (length seq)
                        :element-type '(unsigned-byte 8)
                        :initial-contents seq
                        :adjustable t
                        :fill-pointer t))

         ;; message length in bits
         (m1 (ash (length v) 3))

         ;; chunked words
         (w (make-array 80 :initial-element 0)))

    ;; append the '1' bit to the end of the message
    (vector-push-extend #x80 v)

    ;; make the message congruent to 448 bits (mod 512) in length
    (do ()
        ((= (rem (length v) 64) 56))
      (vector-push-extend #x00 v))

    ;; append message length as a 64-bit, big-endian value to the message
    (do ((i 56 (- i 8)))
        ((minusp i))
      (vector-push-extend (logand (ash m1 (- i)) #xff) v))

    ;; break the message up into 512-bit chunks
    (do ((chunk 0 (+ chunk 64)))
        ((>= chunk (length v))

         ;; produce the final digest
         (hash-digest (logior (ash h0 128)
                              (ash h1 96)
                              (ash h2 64)
                              (ash h3 32)
                              (ash h4 0))))

      ;; break each chunk into 32-bit, big-endian words
      (dotimes (i 80)
        (setf (aref w i)
              (if (< i 16)
                  (word v chunk (* i 4))
                (rotate-word (logxor (aref w (- i 3))
                                     (aref w (- i 8))
                                     (aref w (- i 14))
                                     (aref w (- i 16)))))))

      ;; process each chunk
      (let ((a h0)
            (b h1)
            (c h2)
            (d h3)
            (e h4))
        (dotimes (i 80)
          (multiple-value-bind (k f)
              (cond ((<= 0 i 19)
                     (values #x5a827999 (logxor d (logand b (logxor c d)))))
                    ((<= 20 i 39)
                     (values #x6ed9eba1 (logxor b c d)))
                    ((<= 40 i 59)
                     (values #x8f1bbcdc (logxor (logand b c)
                                                (logand b d)
                                                (logand c d))))
                    ((<= 60 i 79)
                     (values #xca62c1d6 (logxor b c d))))
            (let ((x (logand (+ (rotate-word a 5) f e k (aref w i)) #xffffffff)))
              (setf e d d c c (rotate-word b 30) b a a x))))

        ;; add this chunk to the hash result
        (setf h0 (logand (+ h0 a) #xffffffff))
        (setf h1 (logand (+ h1 b) #xffffffff))
        (setf h2 (logand (+ h2 c) #xffffffff))
        (setf h3 (logand (+ h3 d) #xffffffff))
        (setf h4 (logand (+ h4 e) #xffffffff))))))

;;; ----------------------------------------------------

(defun sha1-digest (message)
  "Return the SHA1 digest for a byte sequence."
  (digest (hash-vector message)))

;;; ----------------------------------------------------

(defun sha1-hex (message)
  "Return the SHA1 hex digest for a byte sequence."
  (format nil "~{~16,2,'0r~}" (sha1-digest message)))

;;; ----------------------------------------------------

(defun sha1-base64 (message &optional (base64-encoder *base64-encoder*))
  "Return the SHA1 base64-encoded digest for a byte sequence."
  (check-type base64-encoder function-designator)
  (funcall base64-encoder (map 'string #'code-char (sha1-digest message))))

;;; ----------------------------------------------------

(defun hmac-sha1-digest (key message)
  "Return the HMAC-SHA1 digest for a byte sequence."
  (when (> (length key) 64)
    (setf key (sha1-digest key)))

  ;; make sure the key is at least blocksize in length
  (when (< (length key) 64)
    (setf key (replace (make-array 64
                                   :initial-element 0
                                   :element-type '(unsigned-byte 8))

                       ;; make sure the key is a byte vector
                       (hash-vector key))))

  ;; determine the o-key-pad and i-key-pad
  (let* ((o-key (loop for i across key collect (logxor #x5c i)))
         (i-key (loop for i across key collect (logxor #x36 i)))

         ;; digest the i-key and hash of the message
         (l-msg (concatenate 'list i-key (hash-vector message))))

    ;; generate the HMAC hash
    (sha1-digest (append o-key (sha1-digest l-msg)))))

;;; ----------------------------------------------------

(defun hmac-sha1-hex (key message)
  "Return the HMAC-SHA1 hex digest for a byte sequence."
  (format nil "~{~16,2,'0r~}" (hmac-sha1-digest key message)))

;;; ----------------------------------------------------

(defun hmac-sha1-base64 (key message &optional (base64-encoder *base64-encoder*))
  "Return the HMAC-SHA1 base64-encoded digest for a byte sequence."
  (check-type base64-encoder function-designator)
  (funcall base64-encoder (map 'string #'code-char (hmac-sha1-digest key message))))
