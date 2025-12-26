// native cocoa ui for mac users

#import <Cocoa/Cocoa.h>
#import <QuartzCore/QuartzCore.h>
#import <objc/runtime.h>


extern char *load_decrypted_vault(const char *password, unsigned char *salt);
extern void save_encrypted_vault(const char *password, const char *data,
                                 unsigned char *salt);
extern void copy_to_clipboard(const char *text);

@interface VaultApp : NSApplication
@end

@implementation VaultApp
@end

@interface VaultWindowDelegate : NSObject <NSWindowDelegate>
@end

@implementation VaultWindowDelegate
- (BOOL)windowShouldClose:(id)sender {
  [NSApp terminate:nil];
  return YES;
}
@end

@interface VaultViewController
    : NSViewController <NSTableViewDelegate, NSTableViewDataSource>
@property(strong) NSSecureTextField *masterPassField;
@property(strong) NSView *loginView;
@property(strong) NSView *dashboardView;
@property(strong) NSTableView *tableView;
@property(strong) NSMutableArray *entries;
@property(strong) NSArray *filteredEntries;
@property(strong) NSSearchField *searchField;
@property(strong) NSString *masterPassword;
@property(strong) NSVisualEffectView *glassView;
@end

@implementation VaultViewController

- (void)loadView {
  self.view = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 700, 500)];
  self.view.wantsLayer = YES;

 
  self.glassView = [[NSVisualEffectView alloc] initWithFrame:self.view.bounds];
  self.glassView.material =
      NSVisualEffectMaterialHeaderView; 
  self.glassView.blendingMode = NSVisualEffectBlendingModeBehindWindow;
  self.glassView.state = NSVisualEffectStateActive;
  self.glassView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  [self.view addSubview:self.glassView];

  [self setupLoginView];
}

- (void)setupLoginView {
  self.loginView = [[NSView alloc] initWithFrame:self.view.bounds];
  self.loginView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
  [self.view addSubview:self.loginView];

  
  NSView *card = [[NSView alloc] initWithFrame:NSMakeRect(200, 150, 300, 250)];
  card.wantsLayer = YES;
  card.layer.backgroundColor =
      [NSColor colorWithDeviceWhite:1.0 alpha:0.4].CGColor;
  card.layer.cornerRadius = 20;
  card.layer.borderWidth = 1.0;
  card.layer.borderColor = [NSColor colorWithDeviceWhite:1.0 alpha:0.6].CGColor;
  [self.loginView addSubview:card];

  NSTextField *titleLabel = [NSTextField labelWithString:@"Vault Native"];
  titleLabel.font = [NSFont boldSystemFontOfSize:28];
  titleLabel.textColor = [NSColor colorWithDeviceWhite:0.1 alpha:0.9];
  titleLabel.frame = NSMakeRect(0, 180, 300, 40);
  titleLabel.alignment = NSTextAlignmentCenter;
  [card addSubview:titleLabel];

  self.masterPassField =
      [[NSSecureTextField alloc] initWithFrame:NSMakeRect(50, 110, 200, 32)];
  self.masterPassField.placeholderString = @"Master Password";
  self.masterPassField.bezeled = NO;
  self.masterPassField.drawsBackground = YES;
  self.masterPassField.backgroundColor = [NSColor colorWithDeviceWhite:1.0
                                                                 alpha:0.5];
  self.masterPassField.wantsLayer = YES;
  self.masterPassField.layer.cornerRadius = 8;
  self.masterPassField.action = @selector(performLogin:);
  self.masterPassField.target = self;
  [card addSubview:self.masterPassField];

  NSButton *loginBtn = [NSButton buttonWithTitle:@"Unlock Vault"
                                          target:self
                                          action:@selector(performLogin:)];
  loginBtn.frame = NSMakeRect(50, 60, 200, 40);
  loginBtn.bezelStyle = NSBezelStyleRounded;
  [card addSubview:loginBtn];
}

- (void)performLogin:(id)sender {
  NSString *pass = self.masterPassField.stringValue;
  unsigned char salt[16];
  char *data = load_decrypted_vault([pass UTF8String], salt);

  if (data) {
    self.masterPassword = pass;
    self.entries = [NSMutableArray array];
    NSString *vaultString = [NSString stringWithUTF8String:data];
    NSArray *lines = [vaultString componentsSeparatedByString:@"\n"];
    for (NSString *line in lines) {
      NSArray *parts = [line
          componentsSeparatedByCharactersInSet:[NSCharacterSet
                                                   whitespaceCharacterSet]];
      if (parts.count >= 3) {
        [self.entries addObject:@{
          @"service" : parts[0],
          @"username" : parts[1],
          @"password" : parts[2]
        }];
      }
    }
    free(data);
    self.filteredEntries = [self.entries copy];
    [self showDashboard];
  } else {
    NSAlert *alert = [[NSAlert alloc] init];
    [alert setMessageText:@"Access Denied"];
    [alert setInformativeText:@"The master password you entered is incorrect."];
    [alert runModal];
  }
}

- (void)showDashboard {
  CATransition *transition = [CATransition animation];
  transition.type = kCATransitionFade;
  transition.duration = 0.5;
  [self.view.layer addAnimation:transition forKey:nil];

  [self.loginView removeFromSuperview];
  self.dashboardView = [[NSView alloc] initWithFrame:self.view.bounds];
  self.dashboardView.autoresizingMask =
      NSViewWidthSizable | NSViewHeightSizable;
  [self.view addSubview:self.dashboardView];

  
  NSVisualEffectView *headerBlur =
      [[NSVisualEffectView alloc] initWithFrame:NSMakeRect(0, 420, 700, 80)];
  headerBlur.material = NSVisualEffectMaterialSelection;
  headerBlur.blendingMode = NSVisualEffectBlendingModeWithinWindow;
  [self.dashboardView addSubview:headerBlur];

  self.searchField =
      [[NSSearchField alloc] initWithFrame:NSMakeRect(20, 10, 450, 30)];
  self.searchField.target = self;
  self.searchField.action = @selector(filterEntries:);
  [headerBlur addSubview:self.searchField];

  NSButton *addBtn = [NSButton buttonWithTitle:@"+ Add New"
                                        target:self
                                        action:@selector(showAddModal:)];
  addBtn.frame = NSMakeRect(480, 10, 140, 30);
  addBtn.bezelStyle = NSBezelStyleRounded;
  [headerBlur addSubview:addBtn];

  NSScrollView *scrollView =
      [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 20, 660, 390)];
  scrollView.hasVerticalScroller = NO;
  scrollView.drawsBackground = NO;
  scrollView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

  self.tableView = [[NSTableView alloc] initWithFrame:scrollView.bounds];
  NSTableColumn *col = [[NSTableColumn alloc] initWithIdentifier:@"Entry"];
  col.headerCell.stringValue = @"";
  col.width = 640;
  [self.tableView addTableColumn:col];
  self.tableView.delegate = self;
  self.tableView.dataSource = self;
  self.tableView.headerView = nil;
  self.tableView.backgroundColor = [NSColor clearColor];
  self.tableView.rowHeight = 85;
  self.tableView.selectionHighlightStyle =
      NSTableViewSelectionHighlightStyleNone;

  scrollView.documentView = self.tableView;
  [self.dashboardView addSubview:scrollView];
}

- (void)filterEntries:(id)sender {
  NSString *query = self.searchField.stringValue;
  if (query.length == 0) {
    self.filteredEntries = [self.entries copy];
  } else {
    NSPredicate *pred =
        [NSPredicate predicateWithFormat:@"service CONTAINS[cd] %@", query];
    self.filteredEntries = [self.entries filteredArrayUsingPredicate:pred];
  }
  [self.tableView reloadData];
}

- (void)showAddModal:(id)sender {
  NSAlert *alert = [[NSAlert alloc] init];
  alert.messageText = @"Add New Secret";
  [alert addButtonWithTitle:@"Encrypt & Save"];
  [alert addButtonWithTitle:@"Cancel"];

  NSTextField *svc =
      [[NSTextField alloc] initWithFrame:NSMakeRect(0, 70, 240, 24)];
  svc.placeholderString = @"Service (e.g. GitHub)";
  NSTextField *user =
      [[NSTextField alloc] initWithFrame:NSMakeRect(0, 35, 240, 24)];
  user.placeholderString = @"Identifier/Email";
  NSSecureTextField *pass =
      [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 240, 24)];
  pass.placeholderString = @"Security Key";

  NSView *container = [[NSView alloc] initWithFrame:NSMakeRect(0, 0, 240, 100)];
  [container addSubview:svc];
  [container addSubview:user];
  [container addSubview:pass];
  [alert setAccessoryView:container];

  if ([alert runModal] == NSAlertFirstButtonReturn) {
    NSDictionary *newEntry = @{
      @"service" : svc.stringValue,
      @"username" : user.stringValue,
      @"password" : pass.stringValue
    };
    [self.entries addObject:newEntry];
    [self filterEntries:nil];

    NSMutableString *newData = [NSMutableString string];
    for (NSDictionary *e in self.entries) {
      [newData appendFormat:@"%@ %@ %@\n", e[@"service"], e[@"username"],
                            e[@"password"]];
    }
    save_encrypted_vault([self.masterPassword UTF8String], [newData UTF8String],
                         NULL);
  }
}


- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
  return self.filteredEntries.count;
}

- (NSView *)tableView:(NSTableView *)tableView
    viewForTableColumn:(NSTableColumn *)tableColumn
                   row:(NSInteger)row {
  NSView *rowView = [tableView makeViewWithIdentifier:@"RowView" owner:self];
  if (rowView == nil) {
    rowView =
        [[NSView alloc] initWithFrame:NSMakeRect(0, 0, tableColumn.width, 85)];
    rowView.identifier = @"RowView";

    
    NSView *card = [[NSView alloc]
        initWithFrame:NSMakeRect(0, 5, tableColumn.width - 10, 75)];
    card.wantsLayer = YES;
    card.layer.cornerRadius = 14;
    card.layer.backgroundColor =
        [NSColor colorWithDeviceWhite:1.0 alpha:0.3].CGColor;
    card.layer.borderWidth = 1.0;
    card.layer.borderColor =
        [NSColor colorWithDeviceWhite:1.0 alpha:0.4].CGColor;
    card.identifier = @"card"; 
    [rowView addSubview:card];

    NSTextField *svcLabel =
        [[NSTextField alloc] initWithFrame:NSMakeRect(15, 38, 500, 25)];
    svcLabel.font = [NSFont boldSystemFontOfSize:17];
    svcLabel.textColor = [NSColor colorWithDeviceWhite:0.1 alpha:0.9];
    svcLabel.editable = NO;
    svcLabel.bezeled = NO;
    svcLabel.drawsBackground = NO;
    svcLabel.tag = 101;
    [card addSubview:svcLabel];

    NSTextField *userLabel =
        [[NSTextField alloc] initWithFrame:NSMakeRect(15, 12, 500, 20)];
    userLabel.font = [NSFont systemFontOfSize:13];
    userLabel.textColor = [NSColor colorWithDeviceWhite:0.3 alpha:0.8];
    userLabel.editable = NO;
    userLabel.bezeled = NO;
    userLabel.drawsBackground = NO;
    userLabel.tag = 102;
    [card addSubview:userLabel];
  }

  NSDictionary *e = self.filteredEntries[row];
  NSView *card = nil;
  for (NSView *v in rowView.subviews) {
    if ([v.identifier isEqualToString:@"card"]) {
      card = v;
      break;
    }
  }
  ((NSTextField *)[card viewWithTag:101]).stringValue = e[@"service"];
  ((NSTextField *)[card viewWithTag:102]).stringValue = e[@"username"];
  return rowView;
}

- (BOOL)tableView:(NSTableView *)tableView shouldSelectRow:(NSInteger)row {
  NSDictionary *e = self.filteredEntries[row];
  copy_to_clipboard([e[@"password"] UTF8String]);

  
  NSView *v = nil;
  NSView *container = [tableView viewAtColumn:0 row:row makeIfNecessary:NO];
  for (NSView *sub in container.subviews) {
    if ([sub.identifier isEqualToString:@"card"]) {
      v = sub;
      break;
    }
  }

  if (v) {
    [NSAnimationContext
        runAnimationGroup:^(NSAnimationContext *_Nonnull context) {
          context.duration = 0.1;
          v.animator.alphaValue = 0.5;
        }
        completionHandler:^{
          [NSAnimationContext
              runAnimationGroup:^(NSAnimationContext *_Nonnull context) {
                context.duration = 0.2;
                v.animator.alphaValue = 1.0;
              }
              completionHandler:nil];
        }];
  }

  return YES;
}

@end

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    [VaultApp sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

    NSRect frame = NSMakeRect(0, 0, 700, 500);
    NSWindow *window = [[NSWindow alloc]
        initWithContentRect:frame
                  styleMask:(NSWindowStyleMaskTitled |
                             NSWindowStyleMaskClosable |
                             NSWindowStyleMaskMiniaturizable |
                             NSWindowStyleMaskFullSizeContentView)
                    backing:NSBackingStoreBuffered
                      defer:NO];
    [window setTitle:@"Vault Native"];
    window.titlebarAppearsTransparent = YES;
    window.titleVisibility = NSWindowTitleHidden;
    window.hasShadow = YES;
    [window setMovableByWindowBackground:YES];
    [window setBackgroundColor:[NSColor clearColor]];
    [window setOpaque:NO];
    [window center];

    VaultWindowDelegate *delegate = [[VaultWindowDelegate alloc] init];
    [window setDelegate:delegate];

    VaultViewController *vc = [[VaultViewController alloc] init];
    window.contentViewController = vc;

    [window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [NSApp run];
  }
  return 0;
}
