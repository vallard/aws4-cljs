; light weight lib to give you headers for aws sig4 requests. RTFM here:  
; http://docs.aws.amazon.com/general/latest/gr/signing_aws_api_requests.html
(ns dash.aws4
  (:require [goog.crypt.Sha256 :as sha256]
            [goog.crypt.Hmac :as Hmac]
            [goog.crypt :as crypt]
            [goog.crypt.base64 :refer [encodeString decodeString]]
            [reagent.core :as r ]
            [cemerick.url :refer [url-encode url-decode]])
  (:import [goog.crypt Hmac Sha256]))

; magical headers lifted from: 
; https://github.com/nervous-systems/eulalie/blob/master/src/eulalie/sign.cljc
(def KEY-PREFIX "AWS4")
(def MAGIC-SUFFIX "aws4_request")
(def ALGORITHM "AWS4-HMAC-SHA256")

; used by the string to sha256 function to run the digest of the string.
(defn digest [hasher the-bytes]
  (.update hasher the-bytes)
  (.digest hasher))

; take a string and make a 256 bit (32 byte) hash out of it. 
(defn str->sha256 [s]
  (goog.crypt/byteArrayToHex (digest (Sha256.) (goog.crypt/stringToByteArray s))))

;; Simple function used to add string to the auth header at the end. 
(defn path-string 
  [date access-key region service ]
  (str 
      access-key "/"
      (.slice date 0, 8) "/" region "/" service "/" MAGIC-SUFFIX ))

; Task 1: Create a canonical request.  
; http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

; The value passed in is a hash that looks like:
;  {:method "GET" :path "/" :query-string "Action=ListUsers&Version=2010-05-08" 
;   :headers {:host "iam.amazonaws.com" :x-amz-date "2018030T123600Z" :content-type "blah"
;   :payload {"some" : "json"}} 

; TODO: Some things are missing:  We don't sort the query strings at the moment and we've only tested
; the payload with an empty string.  
(defn canonical-request [params]
  (str  (params :method) "\n"  
        (params :path) "\n"
        (params :query-string) "\n"
        (clojure.string/join "\n" 
          (map #(str (name %) ":" ((params :headers) %)) 
            (sort (keys (params :headers))))) "\n"
        "\n"
        (clojure.string/join ";" (sort (map name (keys (params :headers))))) "\n"
        (str->sha256 (params :payload))
      ))

; Task 2: Create the String to Sign.   
; http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
(defn string-to-sign
  [date region method service signed-canonical-request]
    (str ALGORITHM "\n"
         date "\n"
         (.slice date 0 8) "/" region "/" service "/" MAGIC-SUFFIX "\n"
         signed-canonical-request)) 
       
; this is encodes in hmac-sha256
; inspired from: 
; https://github.com/nervous-systems/balonius/blob/cf93925f2e0ffe0a76f845194d1949cf1c2626f1/src/balonius/platform/sign.cljs
(defn hmac-sha256 [s k]
  (let [s (goog.crypt/stringToByteArray s)
        k (goog.crypt/stringToByteArray k)]
    (-> (Sha256.) (Hmac. s) (.getHmac k)) ))

; Task 3: Calculate the signature.  This is done by hashing and hashing and hashing... 
; see: http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
(defn signing-key 
  [k date-stamp region-name service-name]
  (let [ kDate (hmac-sha256 (str "AWS4" k) date-stamp )
         kRegion (hmac-sha256 (goog.crypt/byteArrayToString kDate) region-name)
         kService (hmac-sha256 (goog.crypt/byteArrayToString kRegion) service-name)
         kSigning (hmac-sha256 (goog.crypt/byteArrayToString kService) MAGIC-SUFFIX)]
    {:kDate kDate :kRegion kRegion :kService kService :kSigning kSigning}))

      
; This function tests the signing key.  We use it to make sure our functions give what AWS says it should. 
; See the documentation here: 
; http://docs.aws.amazon.com/general/latest/gr/signature-v4-examples.html
; notice the end of the page shows what the signatures should be. 
; we don't use the functions in the library but instead they were used to test the library. 
(defn test-signing-key2 []
  (let [kSign (signing-key "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        "20120215"
        "us-east-1"
        "iam")]
      (print "kDate should equal: 969fbb94feb542b71ede6f87fe4d5fa29c789342b0f407474670f0c2489e0a0d  Actual Value: " (goog.crypt/byteArrayToHex (kSign :kDate)))
      (print "kRegion should equal: 69daa0209cd9c5ff5c8ced464a696fd4252e981430b10e3d3fd8e2f197d7a70c Actual Value: " (goog.crypt/byteArrayToHex (kSign :kRegion)))
      (print "kService should equal: f72cfd46f26bc4643f06a11eabb6c0ba18780c19a8da0c31ace671265e3c87fa Actual Value: " (goog.crypt/byteArrayToHex (kSign :kService)))
      (print "kSigning should equal: f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d Actual Value: " (goog.crypt/byteArrayToHex (kSign :kSigning)))))


; this test function makes sure that the canonical request is equal to what the AWS documentation
; says it should be. 
; this is from step 1:  http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
(defn test-canonical-request
  []
  (let [cr (canonical-request 
                {:method "GET"
                 :path "/"
                 :query-string "Action=ListUsers&Version=2010-05-08"
                 :headers {:host "iam.amazonaws.com"
                           :x-amz-date "20150830T123600Z"
                           :content-type "application/x-www-form-urlencoded; charset=utf-8" }
                 :payload ""}
                ) ]
    (print "test canonical request is:\n")
    (print cr)
    (str->sha256 cr)))

; this test function makes sure that the string to sign matches what we have in Task 2:
; http://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html  
; The important thing is that the hash of the canonical request must be equal to what is shown in 
; the example.  In this case it was: 
; f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59
(defn test-string-to-sign []
  (let [signed-req (test-canonical-request)
        sts (string-to-sign "20150830T123600Z" "us-east-1" "GET" "iam" signed-req)]
    (print "test string to sign is:\n")
    (print sts)
    sts))

; this test function insures that the signing key is correct so that we can sign the string to sign. 
; This is Task 3 from the documentation: 
; http://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
; The signing string (kSign :kSigning) should be: 
; c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9
; the final Test Signature should then be: 
; 5d672d79c15b13162d9279b0855cfba6789a8edb4c82c400e06b5924a6f2b5d7
(defn test-signing-key []
  (let [kSign (signing-key "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
        "20150830"
        "us-east-1"
        "iam")
        sts (test-string-to-sign)]
    (print "Test signing" (goog.crypt/byteArrayToHex (kSign :kSigning)))
    (print "Test signature" (goog.crypt/byteArrayToHex (hmac-sha256 
              (goog.crypt/byteArrayToString (kSign :kSigning))
              sts)))
              ))
    
; signature - creates the signature for the parameters of the aws4 signing request. It does
; this by creating the canonical-request (Task 1). Next it creates a string to sign (Task 2) by
; encoding the canonical-request hash with some other values.  Then it creates a signature (Task 3).
; finaly it signs the string-to-sign.  This is then added to the headers (Task 4)
(defn signature
  "Added to authorization header for awsv4 signing process"
  [params]
    (let [kSign (signing-key (params :secret-key)
                        (.slice (params :date) 0 8)
                        (params :region)
                        (params :service))
          can-req (canonical-request
                {:method "GET"
                 :path (params :path)
                 :query-string ""
                 :headers {
                           :x-amz-date (params :date)
                           :x-amz-security-token (params :security-token)
                           :host (params :host)
                           :content-type "application/x-www-form-urlencoded" }
                 :payload ""})
          signed-req (str->sha256 can-req)
          sts (string-to-sign (params :date) (params :region) "GET" (params :service) signed-req)]
    (goog.crypt/byteArrayToHex
      (hmac-sha256
        (goog.crypt/byteArrayToString (kSign :kSigning))
         sts ))))

; signed-request will output headers for the AWS signature 4.  This is the main function used in this
; library. Here are the parameters you need to pass in: 
;  - date (long format: 20170602T215453Z) 
;  - credentials-hash:  {:AccessKeyId :SecretAccessKey :SessionToken }
;  - region: us-east-1
;  - service: execute-api
;  - host: wv29k51032.execute-api.us-east-1.amazonaws.com
;  - path: /fun/pets
; At this time this library doesn't support query parameters nor body parameters, but this is something I'll
; probably add in the future. 

(defn signed-request
  [date credentials-hash region service host path]
  ; want to see it all in action for a test case?  Just run test-signing-key: 
  ;(test-signing-key)
  (let [sig (signature {:date date
                        :secret-key (credentials-hash :SecretAccessKey)
                        :security-token (credentials-hash :SessionToken)
                        :region region
                        :service service
                        :host host
                        :path path
                        })]
    { :Authorization 
         (str ALGORITHM
         " Credential=" (path-string date (credentials-hash :AccessKeyId) region service)
         ", SignedHeaders=content-type;host;x-amz-date;x-amz-security-token"
         ", Signature=" sig)
      :X-Amz-Date date
      :X-Amz-Security-Token (credentials-hash :SessionToken)
      :Content-Type "application/x-www-form-urlencoded" }))
