
import UIKit
import Security
class ViewController: UIViewController {
    
    override func viewDidLoad() {
        super.viewDidLoad()
    }
    
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        guard let url = URL(string: "https://www.google.co.in") else { return }
        self.callAPI(withURL: url) { (message) in
            let alert = UIAlertController(title: "SSLPinning", message: message, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
            self.present(alert, animated: true, completion: nil)
        }
    }
    
    func callAPI(withURL url: URL, completion: @escaping (String) -> Void) {
        let session = URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)
        var responseMessage = ""
        let task = session.dataTask(with: url) { (data, response, error) in
            if error != nil {
                print("error: \(error!.localizedDescription): \(error!)")
                responseMessage = "Pinning failed"
            } else if data != nil {
                let str = String(decoding: data!, as: UTF8.self)
                print("Received data:\n\(str)")
                responseMessage = "Certificate pinning is 🚀  successfully completed"
            }
            
            DispatchQueue.main.async {
                completion(responseMessage)
            }
            
        }
        task.resume()
        
    }
}
//--------- SSL pinning by Certificate ---------//

extension ViewController: URLSessionDelegate {
    
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil);
            return
        }
        
        let certificate = SecTrustGetCertificateAtIndex(serverTrust, 0)
        // SSL Policies for domain name check
        let policy = NSMutableArray()
        policy.add(SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString))
        
        //evaluate server certifiacte
        let isServerTrusted = SecTrustEvaluateWithError(serverTrust, nil)
        
        //Local and Remote certificate Data
        let remoteCertificateData:NSData =  SecCertificateCopyData(certificate!)
        let pathToCertificate = Bundle.main.path(forResource: "googlein", ofType: "cer")
        let localCertificateData:NSData = NSData(contentsOfFile: pathToCertificate!)!
        
        //Compare certificates
        if(isServerTrusted && remoteCertificateData.isEqual(to: localCertificateData as Data)){
            let credential:URLCredential =  URLCredential(trust:serverTrust)
            print("Certificate pinning is successfully completed")
            completionHandler(.useCredential,credential)
        }
        else{
            completionHandler(.cancelAuthenticationChallenge,nil)
        }
    }
    
}


