#ifndef SECURITY_CHECKS_H
#define SECURITY_CHECKS_H

#include <stdio.h>

#define MAX_LINE 2048
#define MAX_VIOLATIONS 1000
#define MAX_CODE 8192

typedef enum {
    SQL_INJECTION,
    XSS,
    INFORMATION_LEAKAGE,
    FRAME_INJECTION,
    URL_REDIRECTION,
    MISSING_SESSION_TIMEOUT,
    SENSITIVE_INFO_IN_URL,
    SECURE_COOKIE,
    CROSS_FRAME_SCRIPTING,
    SENSITIVE_INFO_DISPLAY,
    SENSITIVE_INFO_CACHED,
    ENCRYPTION_STRENGTH,
    CRLF_INJECTION,
    TRUST_BOUNDARY_VIOLATION,
    DIRECTORY_TRAVERSAL,
    SESSION_FIXATION,
    RISKY_CRYPTO,
    CREDENTIALS_MANAGEMENT,
    SQL_INJECTION_HIBERNATE,
    IMPROPER_RESOURCE_SHUTDOWN
} SecurityViolation;

extern const char *violation_strings[];

typedef struct {
    char variable_name[MAX_LINE];
    SecurityViolation violation;
    int resolved;
} SecurityIssue;

typedef struct {
    char name[MAX_LINE];
    int is_secure;
} Variable;

extern SecurityIssue issues[MAX_VIOLATIONS];
extern int issue_count;
extern Variable variables[MAX_VIOLATIONS];
extern int variable_count;

void add_issue(const char *variable_name, SecurityViolation violation, int resolved);
void analyze_code(char *code, int line_number, char *filename);

#endif // SECURITY_CHECKS_H
