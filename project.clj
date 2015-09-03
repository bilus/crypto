(defproject bilus/crypto "0.1.3"
  :description  "Small Clojure lib to provide basic GPG keypair generation, encryption & decryption facilities"
  :url          "https://github.com/thi-ng/crypto"
  :license      {:name "Apache Software License 2.0"
                 :url "http://www.apache.org/licenses/LICENSE-2.0"
                 :distribution :repo}
  :scm          {:name "git"
                 :url "git@github.com:thi-ng/crypto.git"}
  :dependencies [[org.clojure/clojure "1.6.0"]]                 
  :profiles {:provided {:dependencies [[org.bouncycastle/bcpg-jdk15on "1.52"]]}
             :dev      {:dependencies [[org.bouncycastle/bcpg-jdk15on "1.52"]]}})
