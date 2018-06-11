//
//  WooDimensions.swift
//  Eightfold
//
//  Created by Brianna Lee on 3/3/18.
//  Copyright © 2018 Owly Design. All rights reserved.
//

import Foundation
import ObjectMapper

/// The dimensions of a product or product variation
public class WooDimensions: Mappable {
    
    /// Product or Variation length.
    public var length: String?
    
    /// Product or Variation width.
    public var width: String?
    
    /// Product or Variation height.
    public var height: String?
    
    public required init?(map: Map) { }
    
    public func mapping(map: Map) {
        length <- map["length"]
        width <- map["width"]
        height <- map["height"]
    }
}
