//
//  KeychainWrapper.h
//  Apple's Keychain Services Programming Guide
//
//  Created by Tim Mitra on 11/17/14.
//  Copyright (c) 2014 Apple. All rights reserved.
//

#import "KeychainWrapper.h"

@implementation KeychainWrapper

-(id) initWithService:(NSString *) service_ withGroup:(NSString*)group_ withKey:(NSString *)key_
{
    self =[super init];
    if(self)
    {
        service = [NSString stringWithString:service_];
        key = [NSString stringWithString:key_];
        @try{
            group = [NSString stringWithString:group_];
        }
        @catch(NSException *exception){
            group = nil;
        }
        
    }
    
    return  self;
}
-(NSMutableDictionary*) prepareDict
{
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
    [dict setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    
    NSData *encodedKey = [key dataUsingEncoding:NSUTF8StringEncoding];
    [dict setObject:encodedKey forKey:(__bridge id)kSecAttrGeneric];
    [dict setObject:encodedKey forKey:(__bridge id)kSecAttrAccount];
    [dict setObject:service forKey:(__bridge id)kSecAttrService];
    [dict setObject:(__bridge id)kSecAttrAccessibleAlwaysThisDeviceOnly forKey:(__bridge id)kSecAttrAccessible];
    
    //This is for sharing data across apps
    if(group != nil)
        [dict setObject:group forKey:(__bridge id)kSecAttrAccessGroup];
    
    return  dict;
    
}
-(BOOL) insertData:(NSString *) data
{
    NSData* valueData = [data dataUsingEncoding:NSUTF8StringEncoding];
    NSMutableDictionary * dict =[self prepareDict];
    [dict setObject:valueData forKey:(__bridge id)kSecValueData];
    
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)dict, NULL);
    if(errSecSuccess != status) {
        NSLog(@"Unable add item with key =%@ error:%d",key,(int)status);
    }
    return (errSecSuccess == status);
}
-(NSData *) getData
{
    NSMutableDictionary *dict = [self prepareDict];
    [dict setObject:(__bridge id)kSecMatchLimitOne forKey:(__bridge id)kSecMatchLimit];
    [dict setObject:(id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)dict,&result);
    
    if( status != errSecSuccess) {
        NSLog(@"Unable to fetch item for key %@ with error:%d",key,(int)status);
        return nil;
    }
    
    return (__bridge NSData *)result;
}

-(BOOL) updateData:(NSString*) data
{
    NSMutableDictionary * dictKey =[self prepareDict];
    
    NSMutableDictionary * dictUpdate =[[NSMutableDictionary alloc] init];
    [dictUpdate setObject:[data dataUsingEncoding:NSUTF8StringEncoding] forKey:(__bridge id)kSecValueData];
    
    
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)dictKey, (__bridge CFDictionaryRef)dictUpdate);
    if(errSecSuccess != status) {
        NSLog(@"Unable add update with key =%@ error:%d",key,(int)status);
    }
    return (errSecSuccess == status);
}

-(BOOL) removeData
{
    NSMutableDictionary *dict = [self prepareDict];
    OSStatus status = SecItemDelete((__bridge CFDictionaryRef)dict);
    if( status != errSecSuccess) {
        NSLog(@"Unable to remove item for key %@ with error:%d",key,(int)status);
        return NO;
    }
    return  YES;
}

-(BOOL) removeAllData
{
    NSMutableDictionary *dict = [[NSMutableDictionary alloc] init];
    [dict setObject:(__bridge id)kSecClassGenericPassword forKey:(__bridge id)kSecClass];
    
    OSStatus status = SecItemDelete((CFDictionaryRef)dict);
    if(status == errSecSuccess)
        return YES;
    return NO;

}

- (BOOL)deleteInternetCredentials:(NSString *)server withGroup:(NSString* __nullable)group
{
  NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
  [query setObject:(__bridge id)(kSecClassInternetPassword) forKey:(__bridge id)kSecClass];
  
  [query setObject:server forKey:(__bridge NSString *)kSecAttrServer];
  [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge NSString *)kSecReturnAttributes];
  [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge NSString *)kSecReturnData];
  
  if(group && group != nil)
      query[(__bridge NSString *)kSecAttrAccessGroup] = group;
  OSStatus status = SecItemDelete((__bridge CFDictionaryRef) query);
  if(status == errSecSuccess)
      return YES;
  return NO;
}

- (BOOL)insertKeychainEntry:(NSDictionary *)attributes
                withOptions:(NSDictionary * __nullable)options
{
  NSString *accessGroup = accessGroupValue(options);
  CFStringRef accessible = accessibleValue(options);
  SecAccessControlCreateFlags accessControl = accessControlValue(options);

  NSMutableDictionary *mAttributes = attributes.mutableCopy;

  if (accessControl) {
    // TO DO IF Needed in Future
  } else {
    mAttributes[(__bridge NSString *)kSecAttrAccessible] = (__bridge id)accessible;
  }

  if (accessGroup != nil) {
    mAttributes[(__bridge NSString *)kSecAttrAccessGroup] = accessGroup;
  }

  attributes = [NSDictionary dictionaryWithDictionary:mAttributes];
  OSStatus osStatus = SecItemAdd((__bridge CFDictionaryRef) attributes, NULL);

  if (osStatus != noErr && osStatus != errSecItemNotFound) {
    return NO;
  } else {
    return YES;
  }
}

-(NSMutableDictionary *) getInternetCredentials:(NSString *)server withGroup:(NSString*)group
{
    NSMutableDictionary *query = [[NSMutableDictionary alloc] init];
    [query setObject:(__bridge id)(kSecClassInternetPassword) forKey:(__bridge id)kSecClass];
    
    [query setObject:server forKey:(__bridge NSString *)kSecAttrServer];
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge NSString *)kSecReturnAttributes];
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge NSString *)kSecReturnData];
    [query setObject:(__bridge NSString *)kSecMatchLimitOne forKey:(__bridge NSString *)kSecMatchLimit];
    
    if(group && group != nil)
        query[(__bridge NSString *)kSecAttrAccessGroup] = group;
     // Look up server in the keychain
     NSDictionary *found = nil;
     CFTypeRef foundTypeRef = NULL;
     OSStatus osStatus = SecItemCopyMatching((__bridge CFDictionaryRef) query, (CFTypeRef*)&foundTypeRef);

     if (osStatus != noErr && osStatus != errSecItemNotFound) {
       return nil;
     }

     found = (__bridge NSDictionary*)(foundTypeRef);
     if (!found) {
       return nil;
     }

     // Found
    NSString *username = (NSString *) [found objectForKey:(__bridge id)(kSecAttrAccount)];
    NSString *password = [[NSString alloc] initWithData:[found objectForKey:(__bridge id)(kSecValueData)] encoding:NSUTF8StringEncoding];
    NSMutableDictionary* responseObj = [NSMutableDictionary dictionaryWithCapacity:2];
    [responseObj setObject:username forKey:@"userName"];
    [responseObj setObject:password forKey:@"Password"];
    CFRelease(foundTypeRef);
    return responseObj;
}

NSString *accessGroupValue(NSDictionary *options)
{
  if (options && options[@"accessGroup"] != nil) {
    return options[@"accessGroup"];
  }
  return nil;
}

CFStringRef accessibleValue(NSDictionary *options)
{
  if (options && options[@"accessible"] != nil) {
    NSDictionary *keyMap = @{
      @"AccessibleWhenUnlocked": (__bridge NSString *)kSecAttrAccessibleWhenUnlocked,
      @"AccessibleAfterFirstUnlock": (__bridge NSString *)kSecAttrAccessibleAfterFirstUnlock,
      @"AccessibleAlways": (__bridge NSString *)kSecAttrAccessibleAlways,
      @"AccessibleWhenPasscodeSetThisDeviceOnly": (__bridge NSString *)kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
      @"AccessibleWhenUnlockedThisDeviceOnly": (__bridge NSString *)kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
      @"AccessibleAfterFirstUnlockThisDeviceOnly": (__bridge NSString *)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
      @"AccessibleAlwaysThisDeviceOnly": (__bridge NSString *)kSecAttrAccessibleAlwaysThisDeviceOnly
    };
    NSString *result = keyMap[options[@"accessible"]];
    if (result) {
      return (__bridge CFStringRef)result;
    }
  }
  return kSecAttrAccessibleAlwaysThisDeviceOnly;
}

SecAccessControlCreateFlags accessControlValue(NSDictionary *options)
{
  // TO DO IF Needed in Future
  return 0;
}

@end
