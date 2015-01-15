(ns thi.ng.crypto.core
  (:require
   [clojure.java.io :as io])
  (:import
   [org.bouncycastle.jce.provider
    BouncyCastleProvider]
   [org.bouncycastle.bcpg
    ArmoredOutputStream
    HashAlgorithmTags]
   [org.bouncycastle.openpgp
    PGPObjectFactory
    PGPPublicKeyRingCollection
    PGPSecretKeyRingCollection
    PGPPublicKey PGPSecretKey
    PGPPublicKeyRing PGPSecretKeyRing
    PGPKeyPair PGPPublicKey
    PGPSecretKey PGPSignature
    PGPCompressedData PGPCompressedDataGenerator
    PGPEncryptedData PGPEncryptedDataList PGPEncryptedDataGenerator
    PGPLiteralData PGPLiteralDataGenerator
    PGPUtil]
   [org.bouncycastle.openpgp.operator.bc
    BcPGPDataEncryptorBuilder
    BcPGPDigestCalculatorProvider
    BcPBESecretKeyDecryptorBuilder
    BcPublicKeyDataDecryptorFactory
    BcPublicKeyKeyEncryptionMethodGenerator]
   [org.bouncycastle.openpgp.operator.jcajce
    JcaPGPContentSignerBuilder
    JcaPGPDigestCalculatorProviderBuilder
    JcaPGPKeyPair
    JcePBESecretKeyEncryptorBuilder]
   [java.util Date UUID]
   [java.io InputStream OutputStream ByteArrayOutputStream FilterOutputStream]
   [java.security
    KeyPair
    KeyPairGenerator
    SecureRandom
    Security]))

(Security/addProvider (BouncyCastleProvider.))

(defn generate-keypair*
  [^String algorithm]
  (fn [bits]
    (let [gen (doto (KeyPairGenerator/getInstance algorithm "BC")
                (.initialize (int bits)))]
      (.generateKeyPair gen))))

(def rsa-keypair     (generate-keypair* "RSA"))
(def dsa-keypair     (generate-keypair* "DSA"))
(def elgamal-keypair (generate-keypair* "ELGAMAL"))

(defn generate-secret-key
  "Generates secret key from given keypair, identity & passphrase."
  [^KeyPair pair ^String ident ^String pass]
  (let [sha1 (.. (JcaPGPDigestCalculatorProviderBuilder.)
                 (build)
                 (get HashAlgorithmTags/SHA1))
        pair (JcaPGPKeyPair. PGPPublicKey/RSA_GENERAL pair (Date.))
        sign (-> pair (.getPublicKey) (.getAlgorithm)
                 (JcaPGPContentSignerBuilder. HashAlgorithmTags/SHA1))
        enc  (-> (JcePBESecretKeyEncryptorBuilder. PGPEncryptedData/CAST5 sha1)
                 (.setProvider "BC")
                 (.build (char-array pass)))]
    (PGPSecretKey.
     PGPSignature/DEFAULT_CERTIFICATION
     pair
     ident
     sha1
     nil
     nil
     sign
     enc)))

(defn export-keypair
  "Takes a secret key and two output targets/streams/filepaths to write
  public & secret keys to. An optional truthy arg can be added to write
  keys as armored ASCII."
  [^PGPSecretKey key out-pub out-sec & [armored?]]
  (let [outp (io/output-stream out-pub)
        outs (io/output-stream out-sec)]
    (with-open [outp (if armored? (ArmoredOutputStream. outp) outp)
                outs (if armored? (ArmoredOutputStream. outs) outs)]
      (-> key (.encode outs))
      (-> key (.getPublicKey) (.encode outp)))))

(defn public-key
  "Retrieves first public key which can be used for encryption from
  given stream/path."
  [path]
  (with-open [in (io/input-stream path)]
    (->> (for [ring (-> (PGPUtil/getDecoderStream in)
                        (PGPPublicKeyRingCollection.)
                        (.getKeyRings)
                        (iterator-seq))
               key  (-> ring (.getPublicKeys) (iterator-seq))]
           key)
         (some #(if (.isEncryptionKey ^PGPPublicKey %) %)))))

(defn secret-key
  "Retrieves first secret key which is usable for signing from given
  stream/path. Also checks that related public key is not revoked."
  [path]
  (with-open [in (io/input-stream path)]
    (->> (for [ring (-> (PGPUtil/getDecoderStream in)
                        (PGPSecretKeyRingCollection.)
                        (.getKeyRings)
                        (iterator-seq))
               key  (-> ring (.getSecretKeys) (iterator-seq))]
           key)
         (some
          #(if (and (.isSigningKey %)
                    (not (.. % (getPublicKey) (isRevoked))))
             %)))))

(defn extract-private-key
  "Takes a secret key & passphrase, extracts encrypted private key."
  [^PGPSecretKey key ^chars pass]
  (.extractPrivateKey
   key (-> (BcPGPDigestCalculatorProvider.)
           (BcPBESecretKeyDecryptorBuilder.)
           (.build pass))))


(defn closing-stream
  [streams]
  (proxy [FilterOutputStream] [(first streams)]
    (close []
      (dorun (map #(.close ^OutputStream %) streams)))))

(defn zipped-stream
  [out buf-size]
  (let [name (str (UUID/randomUUID))
        ld (PGPLiteralDataGenerator.)
        com (PGPCompressedDataGenerator. PGPCompressedData/ZIP)
        zipped-out (.open com out)
        tagged-out (.open ld
                          zipped-out
                          PGPLiteralData/BINARY
                          name
                          (Date.)
                          (byte-array buf-size))]
    (closing-stream [tagged-out zipped-out])))

(defn encrypted-stream
  ^OutputStream
  [^OutputStream out-stream ^PGPPublicKey pub-key buf-size]
  (let [enc (doto (BcPGPDataEncryptorBuilder. PGPEncryptedData/AES_256)
              (.setWithIntegrityPacket true)
              (.setSecureRandom (SecureRandom.)))
        gen (doto (PGPEncryptedDataGenerator. enc)
              (.addMethod (BcPublicKeyKeyEncryptionMethodGenerator. pub-key)))]
    (.open gen out-stream (byte-array buf-size))))


(defn encrypt-stream
  "Takes an input stream, output stream & public key. Writes encrypted
  file to output."
  [in out ^PGPPublicKey pub-key]
  (let [buf-size 0x1000]
    (with-open [e-out (encrypted-stream out pub-key buf-size)
                z-out (zipped-stream e-out buf-size)]
      (io/copy in z-out))))

(defn encrypt-file
  "Takes a in file path, output target path & public key. Writes encrypted
  file to target stream."
  [in out ^PGPPublicKey pub-key]
  (with-open [in-stream (io/input-stream in)
              out-stream (io/output-stream out)]
    (encrypt-stream in-stream out-stream pub-key)))

(defn decrypt-stream
  "Takes a src stream, output stream & public key. Writes decrypted
  file to output."
  [src out sec-key pass]
  (with-open [in  (io/input-stream src)
              out (io/output-stream out)]
    (let [pk  (extract-private-key sec-key (char-array pass))
          in  (-> in (PGPUtil/getDecoderStream) (PGPObjectFactory.))
          enc (.nextObject in)
          enc (if (instance? PGPEncryptedDataList enc) enc (.nextObject in))
          pbe (-> enc (.getEncryptedDataObjects) (.next))
          msg (-> (.getDataStream pbe (BcPublicKeyDataDecryptorFactory. pk))
                  (PGPObjectFactory.)
                  (.nextObject))
          msg (if (instance? PGPCompressedData msg)
                (-> msg (.getDataStream) (PGPObjectFactory.) (.nextObject))
                msg)]
      (if (instance? PGPLiteralData msg)
        (with-open [ld (.getInputStream ^PGPLiteralData msg)]
          (io/copy ld out :buffer-size 0x1000)
          out)))))
