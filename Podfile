
install! 'cocoapods',
         :warn_for_multiple_pod_sources => false

target 'WooOS-iOS' do
  use_frameworks!
  platform :ios, '12.0'
 
  pod 'BraintreeDropIn'
  pod 'Alamofire'
  pod 'ObjectMapper'
  pod 'Locksmith'

  target 'WooOS-iOSTests' do
    inherit! :search_paths
    # Pods for testing
  end
end

target 'WooOS-macOS' do
  use_frameworks!
  platform :osx, '10.12'
  
  pod 'Alamofire'
  pod 'ObjectMapper'
  pod 'Locksmith'

  target 'WooOS-macOSTests' do
    inherit! :search_paths
    # Pods for testing
  end
end

