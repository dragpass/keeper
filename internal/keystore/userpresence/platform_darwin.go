//go:build darwin

package userpresence

/*
#cgo CFLAGS: -x objective-c -fblocks
#cgo LDFLAGS: -framework Cocoa

#include <stdlib.h>
#include <string.h>
#include <dispatch/dispatch.h>
#import <Cocoa/Cocoa.h>

static void dragpass_prepare_application(void) {
    @autoreleasepool {
        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    }
}

static void dragpass_run_application(void) {
    @autoreleasepool {
        [NSApp run];
    }
}

static void dragpass_stop_application(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp stop:nil];
        NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                           location:NSZeroPoint
                                      modifierFlags:0
                                          timestamp:0
                                       windowNumber:0
                                            context:nil
                                            subtype:0
                                              data1:0
                                              data2:0];
        [NSApp postEvent:wake atStart:NO];
    });
}

static int dragpass_confirm(
    const char *title,
    const char *message,
    const char *approve_text,
    const char *deny_text,
    long long timeout_ms
) {
    __block int result = 0;
    void (^show_prompt)(void) = ^{
        @autoreleasepool {
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setAlertStyle:NSAlertStyleInformational];
            [alert setMessageText:[NSString stringWithUTF8String:title]];
            [alert setInformativeText:[NSString stringWithUTF8String:message]];
            [alert addButtonWithTitle:[NSString stringWithUTF8String:approve_text]];
            [alert addButtonWithTitle:[NSString stringWithUTF8String:deny_text]];

            __block BOOL timed_out = NO;
            if (timeout_ms > 0) {
                dispatch_after(
                    dispatch_time(DISPATCH_TIME_NOW, timeout_ms * NSEC_PER_MSEC),
                    dispatch_get_main_queue(),
                    ^{
                        if ([NSApp modalWindow] == [alert window]) {
                            timed_out = YES;
                            [NSApp abortModal];
                            [[alert window] orderOut:nil];
                        }
                    }
                );
            }

            [NSApp activateIgnoringOtherApps:YES];
            NSModalResponse response = [alert runModal];
            result = timed_out ? -1 : (response == NSAlertFirstButtonReturn ? 1 : 0);
        }
    };
    if ([NSThread isMainThread]) {
        show_prompt();
    } else {
        dispatch_sync(dispatch_get_main_queue(), show_prompt);
    }
    return result;
}

static char *dragpass_prompt_secret(
    const char *title,
    const char *message,
    const char *label,
    long long timeout_ms,
    int *status,
    size_t *secret_len
) {
    __block char *secret = NULL;
    void (^show_prompt)(void) = ^{
        @autoreleasepool {
            NSAlert *alert = [[NSAlert alloc] init];
            [alert setAlertStyle:NSAlertStyleInformational];
            [alert setMessageText:[NSString stringWithUTF8String:title]];
            [alert setInformativeText:[NSString stringWithUTF8String:message]];

            NSSecureTextField *field = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 320, 24)];
            [field setPlaceholderString:[NSString stringWithUTF8String:label]];
            [alert setAccessoryView:field];
            [alert addButtonWithTitle:@"Continue"];
            [alert addButtonWithTitle:@"Cancel"];

            __block BOOL timed_out = NO;
            if (timeout_ms > 0) {
                dispatch_after(
                    dispatch_time(DISPATCH_TIME_NOW, timeout_ms * NSEC_PER_MSEC),
                    dispatch_get_main_queue(),
                    ^{
                        if ([NSApp modalWindow] == [alert window]) {
                            timed_out = YES;
                            [NSApp abortModal];
                            [[alert window] orderOut:nil];
                        }
                    }
                );
            }

            [NSApp activateIgnoringOtherApps:YES];
            NSModalResponse response = [alert runModal];
            if (timed_out) {
                *status = -1;
                return;
            }
            if (response != NSAlertFirstButtonReturn) {
                *status = 0;
                return;
            }

            NSData *secret_data = [[field stringValue] dataUsingEncoding:NSUTF8StringEncoding];
            *secret_len = [secret_data length];
            secret = malloc(*secret_len + 1);
            if (secret == NULL) {
                *status = -2;
                return;
            }
            memcpy(secret, [secret_data bytes], *secret_len);
            secret[*secret_len] = '\0';
            *status = 1;
        }
    };
    if ([NSThread isMainThread]) {
        show_prompt();
    } else {
        dispatch_sync(dispatch_get_main_queue(), show_prompt);
    }
    return secret;
}
*/
import "C"

import (
	"context"
	"errors"
	"runtime"
	"time"
	"unsafe"

	"github.com/awnumar/memguard"
)

type cocoaUserPresence struct{}

func NewPlatform() UserPresence {
	return cocoaUserPresence{}
}

// PrepareProcessMainThread must run before other application initialization.
// Locking in main() is too late because the Go scheduler may already have
// moved the main goroutine away from the process's original macOS thread.
func PrepareProcessMainThread() {
	runtime.LockOSThread()
}

// RunHost keeps AppKit on the process main thread while Native Messaging runs
// on a worker goroutine. Cocoa prompts synchronously dispatch onto this event
// loop and therefore never execute on an arbitrary Go runtime thread.
func RunHost(host func()) {
	C.dragpass_prepare_application()
	done := make(chan struct{})
	go func() {
		defer close(done)
		host()
		C.dragpass_stop_application()
	}()
	C.dragpass_run_application()
	<-done
}

func (cocoaUserPresence) Capabilities() Capabilities {
	return Capabilities{
		Available:    true,
		PromptSecret: true,
		Confirm:      true,
		Backend:      "cocoa",
	}
}

func (cocoaUserPresence) ShowRecoveryKey(context.Context, RecoveryKeyPrompt) error {
	return ErrUnavailable
}

func (cocoaUserPresence) PromptSecret(ctx context.Context, prompt SecretPrompt) (SecretResult, error) {
	if err := ctx.Err(); err != nil {
		return SecretResult{}, err
	}
	timeout := effectiveTimeout(ctx, prompt.Timeout)
	if timeout <= 0 {
		return SecretResult{}, context.DeadlineExceeded
	}

	title := C.CString(prompt.Title)
	message := C.CString(prompt.Message)
	label := C.CString(prompt.Label)
	defer C.free(unsafe.Pointer(title))
	defer C.free(unsafe.Pointer(message))
	defer C.free(unsafe.Pointer(label))

	var status C.int
	var secretLen C.size_t
	secret := C.dragpass_prompt_secret(
		title,
		message,
		label,
		C.longlong(timeout.Milliseconds()),
		&status,
		&secretLen,
	)
	if secret != nil {
		defer func() {
			C.memset(unsafe.Pointer(secret), 0, secretLen+1)
			C.free(unsafe.Pointer(secret))
		}()
	}
	switch status {
	case 1:
		if secretLen == 0 {
			return SecretResult{}, ErrEmptySecret
		}
		plain := C.GoBytes(unsafe.Pointer(secret), C.int(secretLen))
		locked := memguard.NewBufferFromBytes(plain)
		for i := range plain {
			plain[i] = 0
		}
		return SecretResult{Secret: locked}, nil
	case 0:
		return SecretResult{}, ErrDenied
	case -1:
		return SecretResult{}, ErrTimedOut
	default:
		return SecretResult{}, errors.New("native secret prompt failed")
	}
}

func (cocoaUserPresence) Confirm(ctx context.Context, prompt ConfirmPrompt) (Decision, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	timeout := effectiveTimeout(ctx, prompt.Timeout)
	if timeout <= 0 {
		return "", context.DeadlineExceeded
	}

	title := C.CString(prompt.Title)
	message := C.CString(prompt.Message)
	approveText := C.CString(prompt.ApproveText)
	denyText := C.CString(prompt.DenyText)
	defer C.free(unsafe.Pointer(title))
	defer C.free(unsafe.Pointer(message))
	defer C.free(unsafe.Pointer(approveText))
	defer C.free(unsafe.Pointer(denyText))

	result := C.dragpass_confirm(
		title,
		message,
		approveText,
		denyText,
		C.longlong(timeout.Milliseconds()),
	)
	switch result {
	case 1:
		return DecisionApprove, nil
	case 0:
		return DecisionDeny, nil
	default:
		return "", ErrTimedOut
	}
}

func effectiveTimeout(ctx context.Context, requested time.Duration) time.Duration {
	timeout := requested
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < timeout {
			timeout = remaining
		}
	}
	return timeout
}
