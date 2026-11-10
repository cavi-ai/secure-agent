#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN
// Public Objective-C adapters retain the macOS 14 API that the newer Swift
// overlay replaces with Network.NWEndpoint on macOS 15.
NENetworkRule *SAFilterLoopbackRule(NSString *host, uint16_t port, NSUInteger prefix);
NSString * _Nullable SAFilterRemoteHost(NEFilterSocketFlow *flow);
uint16_t SAFilterRemotePort(NEFilterSocketFlow *flow);
NS_ASSUME_NONNULL_END
