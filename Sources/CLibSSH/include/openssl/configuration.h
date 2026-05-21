/*
 * Dispatches OpenSSL 4.0.0 generated configuration headers to the Apple
 * platform family that matches the linked libssl XCFramework slice.
 */

#ifndef SSHKIT_OPENSSL_CONFIGURATION_DISPATCH_H
#define SSHKIT_OPENSSL_CONFIGURATION_DISPATCH_H

#if defined(__APPLE__)
#include <TargetConditionals.h>
#if TARGET_OS_OSX || TARGET_OS_MACCATALYST
#include "configuration_macos.h"
#else
#include "configuration_ios.h"
#endif
#else
#error SSHKit's vendored OpenSSL headers only support Apple platforms.
#endif

#endif /* SSHKIT_OPENSSL_CONFIGURATION_DISPATCH_H */
