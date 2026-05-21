#import <SSHKitObjC/SSHKitConnection.h>

@implementation SSHKitSFTPEntry

- (instancetype)initWithFilename:(NSString *)filename {
    return [self initWithFilename:filename attributes:nil];
}

- (instancetype)initWithFilename:(NSString *)filename attributes:(SSHKitSFTPAttributes *)attributes {
    self = [super init];
    if (self) {
        _filename = [filename copy];
        _attributes = attributes;
    }
    return self;
}

@end

@implementation SSHKitSFTPAttributes

- (instancetype)initWithSize:(uint64_t)size
                 permissions:(uint32_t)permissions
                         uid:(uint32_t)uid
                         gid:(uint32_t)gid
                        type:(uint8_t)type
                  accessedAt:(NSDate *)accessedAt
                  modifiedAt:(NSDate *)modifiedAt {
    self = [super init];
    if (self) {
        _size = size;
        _permissions = permissions;
        _uid = uid;
        _gid = gid;
        _type = type;
        _accessedAt = accessedAt;
        _modifiedAt = modifiedAt;
    }
    return self;
}

@end
