#import "SSHCoreOpenSSHClient+Shell.h"

#import "SSHCoreOpenSSHClient+Internal.h"
#import "SSHCoreOpenSSHClient+Commands.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHShellRuntime.h"
#import "SSHKitShell+Private.h"

#include <arpa/inet.h>
#include <string.h>

static BOOL SSHCoreAppendPTYMode(unsigned char *buffer, size_t capacity, size_t *offset, uint8_t opcode, uint32_t value) {
    if (*offset + 5 > capacity) {
        return NO;
    }

    buffer[(*offset)++] = opcode;
    uint32_t encodedValue = htonl(value);
    memcpy(buffer + *offset, &encodedValue, sizeof(encodedValue));
    *offset += sizeof(encodedValue);
    return YES;
}

static size_t SSHCoreSanePTYModes(unsigned char *buffer, size_t capacity) {
    size_t offset = 0;

#define SSHKIT_APPEND_PTY_MODE(opcode, value)                 \
    do {                                                      \
        if (!SSHCoreAppendPTYMode(buffer, capacity, &offset, opcode, value)) { \
            return 0;                                         \
        }                                                     \
    } while (0)

    SSHKIT_APPEND_PTY_MODE(1, 003);     /* VINTR */
    SSHKIT_APPEND_PTY_MODE(2, 034);     /* VQUIT */
    SSHKIT_APPEND_PTY_MODE(3, 0177);    /* VERASE */
    SSHKIT_APPEND_PTY_MODE(4, 025);     /* VKILL */
    SSHKIT_APPEND_PTY_MODE(5, 004);     /* VEOF */
    SSHKIT_APPEND_PTY_MODE(6, 0);       /* VEOL */
    SSHKIT_APPEND_PTY_MODE(7, 0);       /* VEOL2 */
    SSHKIT_APPEND_PTY_MODE(8, 021);     /* VSTART */
    SSHKIT_APPEND_PTY_MODE(9, 023);     /* VSTOP */
    SSHKIT_APPEND_PTY_MODE(10, 032);    /* VSUSP */
    SSHKIT_APPEND_PTY_MODE(12, 022);    /* VREPRINT */
    SSHKIT_APPEND_PTY_MODE(13, 027);    /* VWERASE */
    SSHKIT_APPEND_PTY_MODE(14, 026);    /* VLNEXT */
    SSHKIT_APPEND_PTY_MODE(18, 017);    /* VDISCARD */
    SSHKIT_APPEND_PTY_MODE(34, 0);      /* INLCR */
    SSHKIT_APPEND_PTY_MODE(35, 0);      /* IGNCR */
    SSHKIT_APPEND_PTY_MODE(36, 1);      /* ICRNL */
    SSHKIT_APPEND_PTY_MODE(38, 1);      /* IXON */
    SSHKIT_APPEND_PTY_MODE(42, 1);      /* IUTF8 */
    SSHKIT_APPEND_PTY_MODE(50, 1);      /* ISIG */
    SSHKIT_APPEND_PTY_MODE(51, 1);      /* ICANON */
    SSHKIT_APPEND_PTY_MODE(53, 1);      /* ECHO */
    SSHKIT_APPEND_PTY_MODE(54, 1);      /* ECHOE */
    SSHKIT_APPEND_PTY_MODE(55, 1);      /* ECHOK */
    SSHKIT_APPEND_PTY_MODE(56, 0);      /* ECHONL */
    SSHKIT_APPEND_PTY_MODE(59, 1);      /* IEXTEN */
    SSHKIT_APPEND_PTY_MODE(60, 1);      /* ECHOCTL */
    SSHKIT_APPEND_PTY_MODE(61, 1);      /* ECHOKE */
    SSHKIT_APPEND_PTY_MODE(70, 1);      /* OPOST */
    SSHKIT_APPEND_PTY_MODE(72, 1);      /* ONLCR */
    SSHKIT_APPEND_PTY_MODE(128, 38400); /* ISPEED */
    SSHKIT_APPEND_PTY_MODE(129, 38400); /* OSPEED */

#undef SSHKIT_APPEND_PTY_MODE

    if (offset + 1 > capacity) {
        return 0;
    }
    buffer[offset++] = 0;
    return offset;
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (Shell)

- (nullable SSHKitShell *)openShellWithTerminalType:(NSString *)terminalType
                                            columns:(uint16_t)columns
                                               rows:(uint16_t)rows
                                       eventHandler:(SSHKitShellEventHandler)eventHandler
                                           onClosed:(SSHCoreShellClosedBlock)onClosed
                                              error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:@"shell"
               message:@"SSH shell open started."
              metadata:@{@"terminalType": terminalType,
                         @"columns": [NSString stringWithFormat:@"%hu", columns],
                         @"rows": [NSString stringWithFormat:@"%hu", rows]}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    unsigned char ptyModes[256];
    size_t ptyModesLength = SSHCoreSanePTYModes(ptyModes, sizeof(ptyModes));
    if (ptyModesLength == 0) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeUnavailable, @"Unable to encode SSH shell PTY modes.");
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelDebug
                 phase:@"shell"
               message:@"SSH shell requesting PTY with explicit sane modes."
              metadata:@{@"terminalType": terminalType,
                         @"columns": [NSString stringWithFormat:@"%hu", columns],
                         @"rows": [NSString stringWithFormat:@"%hu", rows],
                         @"ptyModesBytes": [NSString stringWithFormat:@"%lu", (unsigned long)ptyModesLength],
                         @"echo": @"true",
                         @"canonical": @"true"}];

    if (ssh_channel_request_pty_size_modes(channel, terminalType.UTF8String, columns, rows, ptyModes, ptyModesLength) != SSH_OK) {
        [self emitLogLevel:SSHKitLogLevelError
                     phase:@"shell"
                   message:@"SSH shell PTY request failed."
                  metadata:@{@"terminalType": terminalType,
                             @"columns": [NSString stringWithFormat:@"%hu", columns],
                             @"rows": [NSString stringWithFormat:@"%hu", rows],
                             @"ptyModesBytes": [NSString stringWithFormat:@"%lu", (unsigned long)ptyModesLength]}];
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request SSH shell PTY."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelDebug
                 phase:@"shell"
               message:@"SSH shell PTY request succeeded."
              metadata:@{@"terminalType": terminalType,
                         @"columns": [NSString stringWithFormat:@"%hu", columns],
                         @"rows": [NSString stringWithFormat:@"%hu", rows],
                         @"ptyModesBytes": [NSString stringWithFormat:@"%lu", (unsigned long)ptyModesLength]}];

    if (ssh_channel_request_shell(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request SSH shell."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHShellRuntime *runtime = [[SSHCoreLibSSHShellRuntime alloc] initWithChannel:channel
                                                                                workerQueue:self.worker.queue
                                                                                eventHandler:eventHandler
                                                                                    onClosed:^(int32_t exitStatus) {
        [weakSelf clearCurrentTask];
        onClosed(exitStatus);
    } logBlock:^(SSHKitLogLevel level, NSString *phase, NSString *message, NSDictionary<NSString *,NSString *> *metadata) {
        [weakSelf emitLogLevel:level phase:phase message:message metadata:metadata];
    }];
    [self.taskLock lock];
    self.currentTask = runtime;
    BOOL wasCancelled = self.taskCancelled;
    [self.taskLock unlock];
    if (wasCancelled) {
        [runtime closeWithCompletion:^(NSError *closeError) {
            (void)closeError;
        }];
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH shell was cancelled before start.");
        }
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"shell" message:@"SSH shell opened." metadata:@{}];
    return [[SSHKitShell alloc] initWithWriteBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } resizeBlock:^(uint16_t resizeColumns, uint16_t resizeRows, SSHKitCompletion completion) {
        [runtime resizeWithColumns:resizeColumns rows:resizeRows completion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    } startBlock:^{
        [runtime start];
    }];
}

@end

#pragma clang diagnostic pop
