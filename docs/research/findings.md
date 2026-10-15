**Findings: Alex**
*
* Vulnerable Cryptographic Primitives:
  * [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html): Use of a Cryptographic Primitive with a Risky Implementation
    * [CVE-2020-4778](https://www.cve.org/CVERecord?id=CVE-2020-4778): Usage of MD5 algorithm for hashing token in a single instance which is less safe than the default SHA-256 algorithm.
    * [CVE-2019-3907](https://www.cve.org/CVERecord?id=CVE-2019-3907): Storage of user credentials and other sensitive information with a known weak encryption method (MD5 hash of a salt and password).
    * [CVE-2021-34687](https://www.cve.org/CVERecord?id=CVE-2021-34687): Personal key is transmitted over the network using a substitution cipher.
    * [CVE-2020-6616](https://www.cve.org/CVERecord?id=CVE-2020-6616): Chip implementing Bluetooth uses a low-entropy PRNG instead of a hardware RNG, allowing spoofing.
    * see [CWE-1240](https://cwe.mitre.org/data/definitions/1240.html) for more.

* Open-Source Cryptographic **Inventory** Tools:
  * Cryptography Bill of Materials:
    * An object model to describe cryptographic assets (short crypto-assets) and their dependencies. [CBOM](https://github.com/IBM/CBOM?utm_source=chatgpt.com)
  * CBOMkit:
    * A toolset for dealing with Cryptography Bill of Materials (CBOM). [CBOM-kit](https://github.com/IBM/cbomkit?utm_source=chatgpt.com)
* Open-Source Cryptographic **Agility** Tools:
    * **Google's** multi-language, cross-platform, open source library that provides secure and easy-to-use cryptographic APIs.
        [Tink](https://developers.google.com/tink)
    * An open source, unified API that removes the complexity of cryptographic libraries for developers and instead lets them call on the API to do the heavy lifting. [Sandwich](https://www.sandboxaq.com/solutions/sandwich?utm_source=chatgpt.com)
