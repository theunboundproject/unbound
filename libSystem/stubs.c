#include <stdio.h>

// This is a "Stub" for an Apple System function
void _os_log_with_type() {
    printf("[Unbound libSystem] App tried to log something. I'm ignoring it for now.\n");
}

void _objc_msgSend() {
    // This is the most important function in all of iOS.
    // Every button click goes through here.
    printf("[Unbound libobjc] App sent an Objective-C message.\n");
}