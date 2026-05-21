#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHKitAlgorithmInspector : NSObject

+ (nullable NSDictionary<NSString *, NSString *> *)inspectAlgorithmsWithKeyExchangeAlgorithms:(nullable NSString *)keyExchangeAlgorithms
                                                                            hostKeyAlgorithms:(nullable NSString *)hostKeyAlgorithms
                                                                   publicKeyAcceptedAlgorithms:(nullable NSString *)publicKeyAcceptedAlgorithms
                                                                        ciphersClientToServer:(nullable NSString *)ciphersClientToServer
                                                                        ciphersServerToClient:(nullable NSString *)ciphersServerToClient
                                                                            macsClientToServer:(nullable NSString *)macsClientToServer
                                                                            macsServerToClient:(nullable NSString *)macsServerToClient
                                                                             minimumRSAKeySize:(nullable NSNumber *)minimumRSAKeySize
                                                                                        error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
