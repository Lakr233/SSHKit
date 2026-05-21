#import "SSHCoreOpenSSHClient+Commands.h"

#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHCommandRuntime.h"
#import "SSHKitCommand+Private.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (Commands)

- (nullable SSHKitCommandResult *)executeCommand:(NSString *)command error:(NSError **)error {
    return [self executeLibSSHCommand:command requestPTY:NO error:error];
}

- (nullable SSHKitCommandResult *)executePTYCommand:(NSString *)command error:(NSError **)error {
    return [self executeLibSSHCommand:command requestPTY:YES error:error];
}

- (nullable SSHKitCommand *)openCommand:(NSString *)command
                           eventHandler:(SSHKitCommandEventHandler)eventHandler
                               onClosed:(SSHCoreCommandClosedBlock)onClosed
                                  error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo phase:@"command" message:@"SSH streaming command open started." metadata:@{}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (ssh_channel_request_exec(channel, command.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeCommandFailed fallback:@"Unable to execute SSH command."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    __weak SSHCoreOpenSSHClient *weakSelf = self;
    SSHCoreLibSSHCommandRuntime *runtime = [[SSHCoreLibSSHCommandRuntime alloc] initWithChannel:channel
                                                                                   workerQueue:self.worker.queue
                                                                                   eventHandler:eventHandler
                                                                                       onClosed:^(int32_t exitStatus, NSString *exitSignal) {
        [weakSelf clearCurrentTask];
        onClosed(exitStatus, exitSignal);
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
            *error = SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled before start.");
        }
        return nil;
    }

    [self emitLogLevel:SSHKitLogLevelInfo phase:@"command" message:@"SSH streaming command opened." metadata:@{}];
    return [[SSHKitCommand alloc] initWithWriteBlock:^(NSData *data, SSHKitCompletion completion) {
        [runtime writeData:data completion:completion];
    } eofBlock:^(SSHKitCompletion completion) {
        [runtime sendEOFWithCompletion:completion];
    } closeBlock:^(SSHKitCompletion completion) {
        [runtime closeWithCompletion:completion];
    } startBlock:^{
        [runtime start];
    }];
}

- (nullable SSHKitCommandResult *)executeLibSSHCommand:(NSString *)command requestPTY:(BOOL)requestPTY error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:requestPTY ? @"shell" : @"command"
               message:requestPTY ? @"SSH PTY command started." : @"SSH command started."
              metadata:@{}];
    ssh_channel channel = [self openSessionChannelWithError:error];
    if (channel == NULL) {
        return nil;
    }

    if (requestPTY && ssh_channel_request_pty(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to request PTY."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    if (ssh_channel_request_exec(channel, command.UTF8String) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeCommandFailed fallback:@"Unable to execute SSH command."];
        }
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    NSMutableData *standardOutput = [[NSMutableData alloc] init];
    NSMutableData *standardError = [[NSMutableData alloc] init];
    if (![self readLibSSHChannel:channel standardOutput:standardOutput standardError:standardError error:error]) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }

    uint32_t exitStatus = 0;
    char *rawExitSignal = NULL;
    int exitState = ssh_channel_get_exit_state(channel, &exitStatus, &rawExitSignal, NULL);
    if (exitState != SSH_OK) {
        free(rawExitSignal);
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"SSH command finished without an exit status.");
        }
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return nil;
    }
    NSString *exitSignal = rawExitSignal != NULL ? [NSString stringWithUTF8String:rawExitSignal] : nil;
    free(rawExitSignal);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    NSMutableDictionary<NSString *, NSString *> *metadata = [@{@"exitStatus": [NSString stringWithFormat:@"%d", (int32_t)exitStatus]} mutableCopy];
    if (exitSignal.length > 0) {
        metadata[@"exitSignal"] = exitSignal;
    }
    [self emitLogLevel:SSHKitLogLevelInfo
                 phase:requestPTY ? @"shell" : @"command"
               message:requestPTY ? @"SSH PTY command finished." : @"SSH command finished."
              metadata:metadata];
    return [[SSHKitCommandResult alloc] initWithStandardOutput:standardOutput
                                                standardError:standardError
                                                   exitStatus:(int32_t)exitStatus
                                                   exitSignal:exitSignal];
}

- (nullable ssh_channel)openSessionChannelWithError:(NSError **)error {
    if (self.session == NULL) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeInvalidState, @"SSH session is not connected.");
        }
        return NULL;
    }

    ssh_channel channel = ssh_channel_new(self.session);
    if (channel == NULL) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to allocate SSH channel."];
        }
        return NULL;
    }

    if (ssh_channel_open_session(channel) != SSH_OK) {
        if (error) {
            *error = [self libSSHErrorWithCode:SSHKitErrorCodeConnectionFailed fallback:@"Unable to open SSH channel."];
        }
        ssh_channel_free(channel);
        return NULL;
    }

    return channel;
}

- (BOOL)readLibSSHChannel:(ssh_channel)channel
           standardOutput:(NSMutableData *)standardOutput
            standardError:(NSMutableData *)standardError
                    error:(NSError **)error {
    char buffer[32768];
    while (ssh_channel_is_eof(channel) == 0) {
        int stdoutCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 0, 100);
        if (stdoutCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed reading SSH command stdout.");
            }
            return NO;
        }
        if (stdoutCount > 0) {
            [standardOutput appendBytes:buffer length:(NSUInteger)stdoutCount];
        }

        int stderrCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 1, 0);
        if (stderrCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed reading SSH command stderr.");
            }
            return NO;
        }
        if (stderrCount > 0) {
            [standardError appendBytes:buffer length:(NSUInteger)stderrCount];
        }
    }

    for (;;) {
        int stderrCount = ssh_channel_read_timeout(channel, buffer, sizeof(buffer), 1, 0);
        if (stderrCount == SSH_ERROR) {
            if (error) {
                *error = [self isTaskCancelled] ? SSHKitMakeError(SSHKitErrorCodeCancelled, @"SSH command was cancelled.") : SSHKitMakeError(SSHKitErrorCodeCommandFailed, @"Failed draining SSH command stderr.");
            }
            return NO;
        }
        if (stderrCount == 0) {
            return YES;
        }
        [standardError appendBytes:buffer length:(NSUInteger)stderrCount];
    }
}

@end

#pragma clang diagnostic pop
