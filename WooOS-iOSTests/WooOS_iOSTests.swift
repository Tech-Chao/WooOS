//
//  WooOS_iOSTests.swift
//  WooOS-iOSTests
//
//  Created by Brie on 6/12/18.
//

import XCTest
@testable import WooOS_iOS

class WooOS_iOSTests: XCTestCase {
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testExample() {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct results.
        WooAPI(url: URL("https//:www.clashxhub.com"), key: "", secret: "")
    }
    
    func testPerformanceExample() {
        // This is an example of a performance test case.
        self.measure {
            // Put the code you want to measure the time of here.
        }
    }
    
}
