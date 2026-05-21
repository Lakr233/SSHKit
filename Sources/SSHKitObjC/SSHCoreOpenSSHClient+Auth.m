#import "SSHCoreOpenSSHClient+Auth.h"

#import "SSHCoreOpenSSHClient+Internal.h"

#import <SSHKitObjC/SSHKitConfiguration.h>
#import <SSHKitObjC/SSHKitError.h>

#import "SSHCoreLibSSHHelpers.h"

static NSString *SSHCoreStringFromCString(const char *string) {
    return string != NULL ? [NSString stringWithUTF8String:string] : @"";
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"

@implementation SSHCoreOpenSSHClient (Auth)

- (BOOL)authenticateLibSSHSession:(ssh_session)session error:(NSError **)error {
    [self emitLogLevel:SSHKitLogLevelDebug
                 phase:@"auth"
               message:@"SSH authentication method selected."
              metadata:@{@"method": SSHCoreAuthenticationName(self.configuration.authenticationKind)}];
    int rc = SSH_AUTH_DENIED;
    switch (self.configuration.authenticationKind) {
        case SSHKitAuthenticationKindPassword:
            if (self.configuration.password.length == 0) {
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Password authentication requires a password.");
                }
                return NO;
            }
            rc = ssh_userauth_password(session, NULL, self.configuration.password.UTF8String);
            break;
        case SSHKitAuthenticationKindPrivateKeyFile: {
            if (self.configuration.privateKeyPath.length == 0) {
                if (error) {
                    *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Private key authentication requires a key file path.");
                }
                return NO;
            }
            ssh_key privateKey = NULL;
            const char *passphrase = self.configuration.privateKeyPassphrase.length > 0 ? self.configuration.privateKeyPassphrase.UTF8String : NULL;
            if (ssh_pki_import_privkey_file(self.configuration.privateKeyPath.UTF8String, passphrase, NULL, NULL, &privateKey) != SSH_OK) {
                if (error) {
                    *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to import private key."];
                }
                return NO;
            }
            rc = ssh_userauth_publickey(session, NULL, privateKey);
            ssh_key_free(privateKey);
            break;
        }
        case SSHKitAuthenticationKindKeyboardInteractive:
            return [self authenticateKeyboardInteractiveSession:session error:error];
        case SSHKitAuthenticationKindAgent:
            rc = ssh_userauth_agent(session, NULL);
            break;
    }

    if (rc == SSH_AUTH_SUCCESS) {
        return YES;
    }

    if (error) {
        *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"SSH authentication failed."];
    }
    return NO;
}

- (BOOL)authenticateKeyboardInteractiveSession:(ssh_session)session error:(NSError **)error {
    SSHKitKeyboardInteractiveResponder responder = self.configuration.keyboardInteractiveResponder;
    if (responder == nil) {
        if (error) {
            *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Keyboard-interactive authentication requires a response provider.");
        }
        return NO;
    }

    int rc = ssh_userauth_kbdint(session, NULL, NULL);
    while (rc == SSH_AUTH_INFO) {
        NSString *name = SSHCoreStringFromCString(ssh_userauth_kbdint_getname(session));
        NSString *instruction = SSHCoreStringFromCString(ssh_userauth_kbdint_getinstruction(session));
        int promptCount = ssh_userauth_kbdint_getnprompts(session);
        if (promptCount < 0) {
            if (error) {
                *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to read keyboard-interactive prompts."];
            }
            return NO;
        }

        NSMutableArray<SSHKitKeyboardInteractivePrompt *> *prompts = [[NSMutableArray alloc] initWithCapacity:(NSUInteger)promptCount];
        for (int index = 0; index < promptCount; index++) {
            char echo = 0;
            const char *prompt = ssh_userauth_kbdint_getprompt(session, (unsigned int)index, &echo);
            [prompts addObject:[[SSHKitKeyboardInteractivePrompt alloc] initWithPrompt:SSHCoreStringFromCString(prompt) echo:echo != 0]];
        }

        NSArray<NSString *> *answers = responder(name, instruction, prompts);
        if (answers.count != prompts.count) {
            if (error) {
                *error = SSHKitMakeError(SSHKitErrorCodeAuthenticationFailed, @"Keyboard-interactive response count does not match prompt count.");
            }
            return NO;
        }

        for (NSUInteger index = 0; index < answers.count; index++) {
            if (ssh_userauth_kbdint_setanswer(session, (unsigned int)index, answers[index].UTF8String) != SSH_OK) {
                if (error) {
                    *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:@"Unable to send keyboard-interactive answer."];
                }
                return NO;
            }
        }

        rc = ssh_userauth_kbdint(session, NULL, NULL);
    }

    if (rc == SSH_AUTH_SUCCESS) {
        return YES;
    }

    if (error) {
        NSString *fallback = rc == SSH_AUTH_PARTIAL ? @"Keyboard-interactive authentication requires additional methods." : @"Keyboard-interactive authentication failed.";
        *error = [self libSSHErrorWithSession:session code:SSHKitErrorCodeAuthenticationFailed fallback:fallback];
    }
    return NO;
}

@end

#pragma clang diagnostic pop
