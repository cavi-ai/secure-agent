#import "ModelFilterCompat.h"

NENetworkRule *SAFilterLoopbackRule(NSString *host, uint16_t port, NSUInteger prefix) {
    NWHostEndpoint *endpoint = [NWHostEndpoint endpointWithHostname:host port:[NSString stringWithFormat:@"%u",port]];
    return [[NENetworkRule alloc] initWithRemoteNetwork:endpoint remotePrefix:prefix localNetwork:nil localPrefix:0 protocol:NENetworkRuleProtocolTCP direction:NETrafficDirectionOutbound];
}
NSString *SAFilterRemoteHost(NEFilterSocketFlow *flow) {
    NWEndpoint *endpoint = flow.remoteEndpoint;
    return [endpoint isKindOfClass:[NWHostEndpoint class]] ? ((NWHostEndpoint *)endpoint).hostname : nil;
}
uint16_t SAFilterRemotePort(NEFilterSocketFlow *flow) {
    NWEndpoint *endpoint = flow.remoteEndpoint;
    if (![endpoint isKindOfClass:[NWHostEndpoint class]]) return 0;
    NSInteger port = ((NWHostEndpoint *)endpoint).port.integerValue;
    return port > 0 && port <= UINT16_MAX ? (uint16_t)port : 0;
}
