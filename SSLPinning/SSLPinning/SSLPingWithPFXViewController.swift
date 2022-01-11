import Security
import UIKit

class SSLPingWithPFXViewController: UIViewController {

    override func viewDidLoad() {
        super.viewDidLoad()
        // Do any additional setup after loading the view.
    }
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
                self.callAPI()
    }

    private func callAPI() {
        let url = URL(string: "url")
        /// When not pinning, we simply skip setting our own delegate
        let session = URLSession(configuration: URLSessionConfiguration.ephemeral, delegate: self, delegateQueue: nil)
        var urlRequest = URLRequest.init(url:URL(string: "https://approvalapp.api.acceptatie-ds.nl/api/data/TaskList")!)
                urlRequest.cachePolicy = .reloadIgnoringLocalCacheData
                urlRequest.httpMethod = "GET"
                urlRequest.addValue("text/plain", forHTTPHeaderField: "Content-Type")
                urlRequest.setValue("token", forHTTPHeaderField: "Authorization")
        if let url = url {
            let task = session.dataTask(with: urlRequest, completionHandler: { (data, response, error) in
                DispatchQueue.main.async { [weak self] in
                    if data != nil {
                        let str = String(decoding: data!, as: UTF8.self)
                        print("Received data:\n\(str)")
                    }
                    if response != nil { self?.alert(message: "Certificate pinning is 🚀  successfully completed") }
                }
            })
            task.resume()
        }
    }

}
//--------- SSL Pinning with pfx and Certificate ---------//
extension SSLPingWithPFXViewController: URLSessionDelegate {

    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = challenge.protectionSpace.serverTrust, SecTrustGetCertificateCount(trust) > 0 else {
            if let localCertPath = Bundle.main.url(forResource: "PFxFilename", withExtension: "pfx"),
               let localCertData = try?  Data(contentsOf: localCertPath)
            {

                let identityAndTrust : IdentityAndTrust = extractIdentity(certData: localCertData as NSData, certPassword: "Password")
                if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodClientCertificate {

                    let urlCredential:URLCredential = URLCredential(
                        identity: identityAndTrust.identityRef,
                        certificates: identityAndTrust.certArray as [AnyObject],
                        persistence: URLCredential.Persistence.forSession);

                    completionHandler(URLSession.AuthChallengeDisposition.useCredential, urlCredential);

                    return
                }
            }
            // This case will probably get handled by ATS, but still...
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }

        if let serverCertificate = SecTrustGetCertificateAtIndex(trust, 0), let serverCertificateKey = publicKey(for: serverCertificate) {
            if pinnedKeys().contains(serverCertificateKey) {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            } else {
                /// Failing here means that the public key of the server does not match the stored one. This can
                /// either indicate a MITM attack, or that the backend certificate and the private key changed,
                /// most likely due to expiration.
                completionHandler(.cancelAuthenticationChallenge, nil)
//                self.alert(message: "✅ Request failed successfully")
                return
            }
        }
        completionHandler(.cancelAuthenticationChallenge, nil)
        self.alert(message: "🚫 Request failed")
    }

    struct IdentityAndTrust {
        public var identityRef:SecIdentity
        public var trust:SecTrust
        public var certArray:NSArray
    }

    func extractIdentity(certData:NSData, certPassword:String) -> IdentityAndTrust {

        var identityAndTrust:IdentityAndTrust!
        var securityError:OSStatus = errSecSuccess

        var items: CFArray?
        let certOptions: Dictionary = [ kSecImportExportPassphrase as String : certPassword ];

        securityError = SecPKCS12Import(certData, certOptions as CFDictionary, &items);
        if securityError == errSecSuccess {

            let certItems:CFArray = (items as CFArray?)!;
            let certItemsArray:Array = certItems as Array
            let dict:AnyObject? = certItemsArray.first;

            if let certEntry:Dictionary = dict as? Dictionary<String, AnyObject> {


                let identityPointer:AnyObject? = certEntry["identity"];
                let secIdentityRef:SecIdentity = (identityPointer as! SecIdentity?)!;


                let trustPointer:AnyObject? = certEntry["trust"];
                let trustRef:SecTrust = trustPointer as! SecTrust;


                var certRef: SecCertificate?
                SecIdentityCopyCertificate(secIdentityRef, &certRef);
                let certArray:NSMutableArray = NSMutableArray();
                certArray.add(certRef as SecCertificate?);

                identityAndTrust = IdentityAndTrust(identityRef: secIdentityRef, trust: trustRef, certArray: certArray);
            }
        }

        return identityAndTrust;
    }

    private func pinnedKeys() -> [SecKey] {
        var publicKeys: [SecKey] = []

        if let pinnedCertificateURL = Bundle.main.url(forResource: "googlein", withExtension: "cer") {
            do {
                let pinnedCertificateData = try Data(contentsOf: pinnedCertificateURL) as CFData
                if let pinnedCertificate = SecCertificateCreateWithData(nil, pinnedCertificateData), let key = publicKey(for: pinnedCertificate) {
                    publicKeys.append(key)
                }
            } catch {
                // Handle error
            }
        }
        return publicKeys
    }

    private func publicKey(for certificate: SecCertificate) -> SecKey? {
        var publicKey: SecKey?

        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        let trustCreationStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)

        if let trust = trust, trustCreationStatus == errSecSuccess {
            publicKey = SecTrustCopyKey(trust)
        }
        return publicKey
    }
}
extension UIViewController {
    func alert(message: String, title: String = "") {
        let alertController = UIAlertController(title: title, message: message, preferredStyle: .alert)
        let OKAction = UIAlertAction(title: "OK", style: .default, handler: nil)
        alertController.addAction(OKAction)
        self.present(alertController, animated: true, completion: nil)
    }
}
