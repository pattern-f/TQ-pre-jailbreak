//
//  ViewController.m
//  pre-jailbreak
//
//  Created by Quote on 2021/2/19.
//

#import "ViewController.h"
#include "mycommon.h"

extern void (*log_UI)(const char *text);
void log_toView(const char *text);

static ViewController *sharedController = nil;

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UIButton *goButton;
@property (weak, nonatomic) IBOutlet UITextView *textView;

@end

char *Build_resource_path(char *filename)
{
    NSString *resourcePath = [[NSBundle mainBundle] resourcePath];
    if(filename == NULL) {
        return strdup([[resourcePath stringByAppendingString:@"/"] UTF8String]);
    }
    return strdup([[resourcePath stringByAppendingPathComponent:[NSString stringWithUTF8String:filename]] UTF8String]);
}

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.

    sharedController = self;

    self.textView.layer.borderWidth = 1.0;
    self.textView.layer.borderColor = UIColor.lightGrayColor.CGColor;
    self.textView.text = @"";
    // 只有当前行中不包含空格等字符时才生效，sad
    self.textView.textContainer.lineBreakMode = NSLineBreakByCharWrapping;
    [self.goButton setEnabled:FALSE];
    self.goButton.backgroundColor = UIColor.lightGrayColor;

    log_UI = log_toView;

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        sys_init();
        print_os_details();
        dispatch_sync( dispatch_get_main_queue(), ^{
            [[sharedController goButton] setEnabled:TRUE];
            [sharedController goButton].backgroundColor = UIColor.systemBlueColor;
        });
    });
}

- (IBAction)exploitTouchUp:(id)sender {
    NSString *enjoyStr = @"Enjoy it :)";
    if ([[[self.goButton titleLabel] text] isEqualToString:enjoyStr]) {
        return;
    }
    [self.goButton setTitle:@"Exploiting" forState:UIControlStateDisabled];
    [self.goButton setEnabled:FALSE];
    self.goButton.backgroundColor = UIColor.lightGrayColor;
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        void exploit_main(void);
        exploit_main();
        dispatch_sync( dispatch_get_main_queue(), ^{
            [[sharedController goButton] setTitle:enjoyStr forState:UIControlStateNormal];
            [[sharedController goButton] setEnabled:TRUE];
            [sharedController goButton].backgroundColor = UIColor.systemGreenColor;
        });
    });
}

@end

void log_toView(const char *text)
{
    dispatch_sync( dispatch_get_main_queue(), ^{
        [[sharedController textView] insertText:[NSString stringWithUTF8String:text]];
        [[sharedController textView] scrollRangeToVisible:NSMakeRange([sharedController textView].text.length, 1)];
    });
}
