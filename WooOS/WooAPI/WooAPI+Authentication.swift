//
//  WooAPI+Authentication.swift
//  Eightfold
//
//  Created by Brianna Lee on 3/12/18.
//  Copyright © 2018 Owly Design. All rights reserved.
//

import Foundation
import Alamofire
import ObjectMapper
import Locksmith

public extension WooAPI {
    
    /// Generates the HTTP headers with the stored auth token.
    ///
    /// - Parameter token: The stored token to be embedded in the HTTP header
    /// - Returns: ["Authorization" : "Bearer \(token ?? "")"]
    func authHeaders(with token: String?) -> HTTPHeaders? {
        guard let safeToken = token else {
            return nil
        }
        
        let authHeaders: HTTPHeaders = [
            "Authorization": "Bearer \(safeToken)"
        ]
        return authHeaders
    }
    
    /// Generates the URLCredential needed for authenticating with either WooCommerce with the Basic authentication method. This method requires the consumerKey and consumerSecret to be set and copied into the codebase.
    ///
    /// - Returns: URLCredential with consumerKey as user and consumerSecret as password.
    /// - Throws: WooError.managerCredentialsAreNil
    func managerURLCredential() throws -> URLCredential {
        
        guard
            let key = consumerKey,
            let secret = consumerSecret
        else {
            throw WooError.managerCredentialsAreNil(description: "Either the consumer key or the consumer secret has no value.")
        }
        
        return URLCredential(user: key,
                             password: secret,
                             persistence: URLCredential.Persistence.synchronizable)
    }
    
    private func username(from email: String) -> String {
        let at = "@"
        let emailComponents = email.components(separatedBy: at)
        guard let username = emailComponents.first else {
            let error = WooError.noUsernameSet(description: "Failed to seperate username from email.")
            print(error.string, error.localizedDescription)
            return ""
        }
        return username
    }
    
    /// Create a new user and sign them in with supplied first name, last name, username, and password.
    ///
    /// - Parameters:
    ///   - firstName: The first name of the customer.
    ///   - lastName: The last name of the customer.
    ///   - username: The chosen username by the customer.
    ///   - password: The given password by the customer.
    ///   - complete: Asynchronous callback containing a success flag and an error string if failed. If unsuccessful: success = false, error = String.
    public func signUp(with firstName: String,
                       lastName: String,
                       username: String,
                       email: String,
                       and password: String,
                       then complete: @escaping WooCompletion.Success) {
        let authBody = [
            "username": self.username(from: email),
            "email": email,
            "password": password
        ]
        
        guard let url = URL(string: "/wp-json/wp/v2/users/register", relativeTo: siteURL) else {
            complete(false, WooError.invalidURL(description: "Could not build user registration URL."))
            return
        }
        
        alamofireManager.request(url, method: .post, parameters: authBody)
            .validate(statusCode: 200..<300)
            .responseJSON { responseJSON in
                switch responseJSON.result {
                case .success(let value):
                    guard
                        let json = value as? [String: Any],
                        let code = json["code"] as? Int,
                        let message = json["message"] as? String
                    else {
                        complete(false, WooError.couldNotParseJSON(description: "Could not extract JSON data from response."))
                        return
                    }
                    
                    guard code == 200 else {
                        print("WooOS Authentication Response Code was not 200. Instead, it was \(code), with the message \"\(message)\"")
                        complete(false, WooError.signupFailed(description: message))
                        return
                    }
                    
                    complete(true, nil)
                    
                case .failure(let error):
                    complete(false, .unsuccessfulRequestResponse(description: error.localizedDescription))
                }
            }
    }
    
    
    private func getNonce(then complete: @escaping WooCompletion.Token) {
        guard let url = URL(string: "/api/get_nonce/", relativeTo: siteURL) else {
            complete(false, nil, WooError.invalidURL(description: "Could not build nonce URL."))
            return
        }
        
        let parameters: Parameters = ["controller": "user", "method": "register"]
        
        alamofireManager.request(url, parameters: parameters)
            .validate(statusCode: 200..<300)
            .responseJSON { responseJSON in
                switch responseJSON.result {
                case .success(let value):
                    guard
                        let json = value as? [String: Any],
                        let nonce = json["nonce"] as? String
                    else {
                        complete(false, nil, .couldNotParseJSON(description: "Resulting JSON has the wrong format while getting the nonce."))
                        return
                    }
                    
                    complete(true, nonce, nil)
                    
                case .failure(let error):
                    complete(false, nil,.unsuccessfulRequestResponse(description: error.localizedDescription))
                }
            }
    }
    
    /// Login user with supplied username and password.
    ///
    /// - Parameters:
    ///   - username: String of Username provided by User.
    ///   - password: String of Password provided by User.
    ///   - complete: Asynchronous callback containing a success flag and an error string if failed. If unsuccessful: success = false, error = String.
    public func login(with username: String,
                      and password: String,
                      then complete: @escaping WooCompletion.Token) {
        
        // Request token using given username and password
        getToken(with: username, and: password, then: complete)
    }
    
    /// Get a new token with the provided Username and Password of end user. Username and Password is usually obtained from the UI.
    ///
    /// - Parameters:
    ///   - username: String of Username provided by User.
    ///   - password: String of Password provided by User.
    ///   - complete: Asynchronous callback containing a success flag, the token that was requested, and an error string if failed. If unsuccessful: success = false, token = nil, error = String.
    private func getToken(with username: String, and password: String, then complete: @escaping WooCompletion.Token) {
        // Build Request URL to get token
        guard let requestURL = URL(string: "wp-json/jwt-auth/v1/token", relativeTo: siteURL) else {
            complete(false, nil, WooError.cannotConstructURL(description: "Could not build token URL"))
            return
        }
        
        // Build parameters required for getting token
        let tokenParameters = ["username": username, "password": password]
        
        // Make request
        alamofireManager.request(requestURL, method: .post, parameters: tokenParameters)
            .validate(statusCode: 200..<300)
            .responseJSON { responseJSON in
                switch responseJSON.result {
                case .success(let value):
                    guard
                        let json = value as? [String: Any],
                        let newToken = json["token"] as? String
                    else {
                        complete(false, nil, WooError.couldNotGetToken(description: "Failed to get token"))
                        return
                    }
                    
                    self.persistToken(newToken)
                    
                    complete(true, newToken, nil)
                    
                case .failure(let error):
                    complete(false, nil,.unsuccessfulRequestResponse(description: error.localizedDescription))
                }
            }
    }
    /// Log user out by revoking the token on the server, deleting the token locally, and deleting the stored user in `WooOS.main`.
    public func logout(then complete: WooCompletion.Completion? = nil) {
        
        // Remove stored token
        UserDefaults.standard.set(nil, forKey: "token")
        
        // Remove stored customer
        WooOS.main.currentCustomer = nil
        
        complete?()
    }
    
     
    func token() -> String? {
        return UserDefaults.standard.string(forKey: "token")
    }
    
    func persistToken(_ token: String, then complete: WooCompletion.Success? = nil) {
        
        UserDefaults.standard.set(token, forKey: "token")
        
        //        guard
        //            // Unwrap username
        //            let username = WooOS.main.currentCustomer?.username
        //
        //            // Handle nil values
        //            else {
        //                complete(false, WooError.couldNotSaveToken(description: "Invalid username: Username is nil."))
        //                return
        //        }
        //
        //        do {
        //            // Save newValue to keychain
        //            try Locksmith.saveData(data: ["token": token], forUserAccount: username, inService: WooAPI.keychainService)
        //
        //            // Handle errors
        //        } catch {
        //            complete(false, WooError.couldNotSaveToken(description: "Failed saving data with Locksmith: " + error.localizedDescription))
        //        }
        //
        //        complete(true, nil)
    }
    
    /// Confirm the token that is currently in use is still valid.
    ///
    /// - Parameter complete: Completion to confirm whether or not the token was validated successfully.
    private func validate(token: String, then complete: @escaping WooCompletion.Success) {
        
        // Build request URL to validate token
        guard let requestURL = URL(string: "wp-json/jwt-auth/v1/token/validate", relativeTo: siteURL) else {
            complete(false, WooError.cannotConstructURL(description: "Could not build token validation URL"))
            return
        }
        
        // Make request
        alamofireManager.request(requestURL,
                                 method: .post,
                                 headers:  authHeaders(with: token))
        // Handle response
        .responseJSON { response in
            switch response.result {
                   case .success(let value):
                       guard let json = value as? [String: Any],
                             let data = json["data"] as? [String: Any],
                             let status = data["status"] as? Int else {
                           complete(false, .couldNotParseJSON(description: "Could not parse JSON in response to token validation."))
                           return
                       }
                       
                       if status == 200 {
                           complete(true, nil)
                       } else {
                           complete(false, .couldNotParseJSON(description: "Token validation failed with status code \(status)"))
                       }
                       
                   case .failure(let error):
                       complete(false, .unsuccessfulRequestResponse(description: error.localizedDescription))
                   }
        }
    }
}
