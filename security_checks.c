#include "security_checks.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

SecurityIssue issues[MAX_VIOLATIONS];
int issue_count = 0;

Variable variables[MAX_VIOLATIONS];
int variable_count = 0;

const char *violation_strings[] = {
    "SQL Injection",
    "XSS",
    "Information Leakage",
    "Frame Injection",
    "URL Redirection",
    "Missing Session Timeout",
    "Sensitive Information in URL",
    "Secure Cookie",
    "Cross Frame Scripting",
    "Sensitive Information Display",
    "Sensitive Information Cached",
    "Encryption Strength",
    "CRLF Injection",
    "Trust Boundary Violation",
    "Directory Traversal",
    "Session Fixation",
    "Risky Cryptographic Algorithm",
    "Credentials Management",
    "SQL Injection Hibernate",
    "Improper Resource Shutdown"
};

void add_variable(const char *name) {
    if (variable_count >= MAX_VIOLATIONS) {
        return;
    }
    for (int i = 0; i < variable_count; i++) {
        if (strcmp(variables[i].name, name) == 0) {
            return;
        }
    }
    strncpy(variables[variable_count].name, name, MAX_LINE - 1);
    variables[variable_count].name[MAX_LINE - 1] = '\0';
    variables[variable_count].is_secure = 0;
    variable_count++;
}

void mark_variable_secure(const char *name) {
    for (int i = 0; i < variable_count; i++) {
        if (strcmp(variables[i].name, name) == 0) {
            variables[i].is_secure = 1;
            return;
        }
    }
}

void add_issue(const char *variable_name, SecurityViolation violation, int resolved) {
    if (issue_count >= MAX_VIOLATIONS) {
        fprintf(stderr, "Issue array overflow\n");
        return;
    }
    for (int i = 0; i < issue_count; i++) {
        if (strcmp(issues[i].variable_name, variable_name) == 0 && issues[i].violation == violation) {
            if (resolved == 1) {
                issues[i].resolved = 1;
            }
            return;
        }
    }

    if (issue_count < MAX_VIOLATIONS) {
        strncpy(issues[issue_count].variable_name, variable_name, MAX_LINE - 1);
        issues[issue_count].variable_name[MAX_LINE - 1] = '\0';
        issues[issue_count].violation = violation;
        issues[issue_count].resolved = resolved;
        issue_count++;
    }
}

// 보안 체크 함수들 정의

void check_sql_injection(char *code, const char *variable_name) {
    if ((strstr(code, "SELECT") || strstr(code, "INSERT") || strstr(code, "UPDATE") || strstr(code, "DELETE")) &&
        !(strstr(code, "?") || strstr(code, ":") || strstr(code, "bind_param") || strstr(code, "bindValue"))) {
        add_issue(variable_name, SQL_INJECTION, 0);
    } else if (strstr(code, "?") || strstr(code, "bind_param") || strstr(code, "bindValue")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, SQL_INJECTION, 1);
    }
}

void check_xss(char *code, const char *variable_name) {
    if ((strstr(code, "document.write") || strstr(code, "innerHTML") || strstr(code, "outerHTML") || strstr(code, "eval")) &&
        strstr(code, "input")) {
        add_issue(variable_name, XSS, 0);
    } else if (strstr(code, "sanitize")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, XSS, 1);
    }
}

void check_information_leakage(char *code, const char *variable_name) {
    if ((strstr(code, "print") || strstr(code, "echo") || strstr(code, "console.log") || strstr(code, "logger.info")) &&
        (strstr(code, "password") || strstr(code, "secret") || strstr(code, "apikey") || strstr(code, "token"))) {
        add_issue(variable_name, INFORMATION_LEAKAGE, 0);
    } else if (strstr(code, "masked") || strstr(code, "sanitized")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, INFORMATION_LEAKAGE, 1);
    }
}

void check_frame_injection(char *code, const char *variable_name) {
    if (strstr(code, "<iframe") || strstr(code, "<frame")) {
        if (strstr(code, "src=") && (strstr(code, "http://") || strstr(code, "https://"))) {
            add_issue(variable_name, FRAME_INJECTION, 0);
        } else {
            mark_variable_secure(variable_name);
            add_issue(variable_name, FRAME_INJECTION, 1);
        }
    }
}

void check_url_redirection(char *code, const char *variable_name) {
    if (strstr(code, "location.href") || strstr(code, "window.location") || strstr(code, "response.sendRedirect")) {
        if (strstr(code, "http://") || strstr(code, "https://")) {
            add_issue(variable_name, URL_REDIRECTION, 0);
        } else {
            mark_variable_secure(variable_name);
            add_issue(variable_name, URL_REDIRECTION, 1);
        }
    }
}

void check_missing_session_timeout(char *code, const char *variable_name) {
    if (strstr(code, "session")) {
        if (!(strstr(code, "timeout") || strstr(code, "expire") || strstr(code, "expiration"))) {
            add_issue(variable_name, MISSING_SESSION_TIMEOUT, 0);
        } else {
            mark_variable_secure(variable_name);
            add_issue(variable_name, MISSING_SESSION_TIMEOUT, 1);
        }
    }
}

void check_sensitive_info_in_url(char *code, const char *variable_name) {
    if (strstr(code, "GET") || strstr(code, "POST")) {
        if (strstr(code, "password") || strstr(code, "secret") || strstr(code, "apikey") || strstr(code, "token")) {
            add_issue(variable_name, SENSITIVE_INFO_IN_URL, 0);
        }
    }
}

void check_secure_cookie(char *code, const char *variable_name) {
    if (strstr(code, "Set-Cookie")) {
        if (!(strstr(code, "Secure") && strstr(code, "HttpOnly"))) {
            add_issue(variable_name, SECURE_COOKIE, 0);
        } else {
            mark_variable_secure(variable_name);
            add_issue(variable_name, SECURE_COOKIE, 1);
        }
    }
}

void check_cross_frame_scripting(char *code, const char *variable_name) {
    if (strstr(code, "<iframe") || strstr(code, "<frame")) {
        if (strstr(code, "src=") && (strstr(code, "http://") || strstr(code, "https://"))) {
            add_issue(variable_name, CROSS_FRAME_SCRIPTING, 0);
        } else {
            mark_variable_secure(variable_name);
            add_issue(variable_name, CROSS_FRAME_SCRIPTING, 1);
        }
    }
}

void check_sensitive_info_display(char *code, const char *variable_name) {
    if (strstr(code, "print") || strstr(code, "echo") || strstr(code, "console.log") || strstr(code, "alert")) {
        if (strstr(code, "password") || strstr(code, "secret") || strstr(code, "apikey") || strstr(code, "token")) {
            add_issue(variable_name, SENSITIVE_INFO_DISPLAY, 0);
        } else if (strstr(code, "masked") || strstr(code, "sanitized")) {
            mark_variable_secure(variable_name);
            add_issue(variable_name, SENSITIVE_INFO_DISPLAY, 1);
        }
    }
}

void check_sensitive_info_cached(char *code, const char *variable_name) {
    if (strstr(code, "cache") && (strstr(code, "password") || strstr(code, "secret") || strstr(code, "apikey") || strstr(code, "token"))) {
        add_issue(variable_name, SENSITIVE_INFO_CACHED, 0);
    } else if (!(strstr(code, "password") || strstr(code, "secret") || strstr(code, "apikey") || strstr(code, "token"))) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, SENSITIVE_INFO_CACHED, 1);
    }
}

void check_encryption_strength(char *code, const char *variable_name) {
    if ((strstr(code, "encrypt") || strstr(code, "decrypt")) &&
        (strstr(code, "MD5") || strstr(code, "SHA1") || strstr(code, "DES"))) {
        add_issue(variable_name, ENCRYPTION_STRENGTH, 0);
    } else if (strstr(code, "SHA256") || strstr(code, "SHA512")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, ENCRYPTION_STRENGTH, 1);
    }
}

void check_crlf_injection(char *code, const char *variable_name) {
    if (strstr(code, "\r\n")) {
        add_issue(variable_name, CRLF_INJECTION, 0);
    } else {
        mark_variable_secure(variable_name);
        add_issue(variable_name, CRLF_INJECTION, 1);
    }
}

void check_trust_boundary_violation(char *code, const char *variable_name) {
    if (strstr(code, "trust_boundary")) {
        add_issue(variable_name, TRUST_BOUNDARY_VIOLATION, 0);
    } else if (strstr(code, "validate") || strstr(code, "sanitize")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, TRUST_BOUNDARY_VIOLATION, 1);
    }
}

void check_directory_traversal(char *code, const char *variable_name) {
    if (strstr(code, "../") || strstr(code, "..\\")) {
        add_issue(variable_name, DIRECTORY_TRAVERSAL, 0);
    } else if (strstr(code, "realpath")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, DIRECTORY_TRAVERSAL, 1);
    }
}

void check_session_fixation(char *code, const char *variable_name) {
    if (strstr(code, "session")) {
        if (strstr(code, "setId")) {
            add_issue(variable_name, SESSION_FIXATION, 0);
        } else if (strstr(code, "invalidate")) {
            mark_variable_secure(variable_name);
            add_issue(variable_name, SESSION_FIXATION, 1);
        }
    }
}

void check_risky_crypto(char *code, const char *variable_name) {
    if (strstr(code, "encrypt") || strstr(code, "decrypt")) {
        if (strstr(code, "ECB") || strstr(code, "DES") || strstr(code, "MD5") || strstr(code, "SHA1")) {
            add_issue(variable_name, RISKY_CRYPTO, 0);
        } else if (strstr(code, "CBC") || strstr(code, "AES") || strstr(code, "SHA256")) {
            mark_variable_secure(variable_name);
            add_issue(variable_name, RISKY_CRYPTO, 1);
        }
    }
}

void check_credentials_management(char *code, const char *variable_name) {
    if (strstr(code, "password") || strstr(code, "secret") || strstr(code, "key") || strstr(code, "token")) {
        if (strstr(code, "hardcoded") || strstr(code, "plaintext")) {
            add_issue(variable_name, CREDENTIALS_MANAGEMENT, 0);
        } else if (strstr(code, "environment") || strstr(code, "config")) {
            mark_variable_secure(variable_name);
            add_issue(variable_name, CREDENTIALS_MANAGEMENT, 1);
        }
    }
}

void check_sql_injection_hibernate(char *code, const char *variable_name) {
    if ((strstr(code, "createQuery") || strstr(code, "createSQLQuery")) &&
        !(strstr(code, "?") || strstr(code, ":") || strstr(code, "bind"))) {
        add_issue(variable_name, SQL_INJECTION_HIBERNATE, 0);
    } else if (strstr(code, "?") || strstr(code, ":") || strstr(code, "bind")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, SQL_INJECTION_HIBERNATE, 1);
    }
}

void check_improper_resource_shutdown(char *code, const char *variable_name) {
    if ((strstr(code, "open") || strstr(code, "connect")) && !(strstr(code, "close") || strstr(code, "disconnect"))) {
        add_issue(variable_name, IMPROPER_RESOURCE_SHUTDOWN, 0);
    } else if (strstr(code, "close") || strstr(code, "disconnect")) {
        mark_variable_secure(variable_name);
        add_issue(variable_name, IMPROPER_RESOURCE_SHUTDOWN, 1);
    }
}

void analyze_code_block(char *code, const char *filename) {
    char *token = strtok(code, " \n\t{};");
    while (token != NULL) {
        if (strcmp(token, "int") == 0 || strcmp(token, "char") == 0 || strcmp(token, "float") == 0 || strcmp(token, "double") == 0 || strcmp(token, "const") == 0) {
            token = strtok(NULL, " \n\t{};");
            if (token != NULL) {
                add_variable(token);
            }
        } else {
            for (int i = 0; i < variable_count; i++) {
                if (strstr(token, variables[i].name) != NULL) {
                    check_sql_injection(code, variables[i].name);
                    check_xss(code, variables[i].name);
                    check_information_leakage(code, variables[i].name);
                    check_frame_injection(code, variables[i].name);
                    check_url_redirection(code, variables[i].name);
                    check_missing_session_timeout(code, variables[i].name);
                    check_sensitive_info_in_url(code, variables[i].name);
                    check_secure_cookie(code, variables[i].name);
                    check_cross_frame_scripting(code, variables[i].name);
                    check_sensitive_info_display(code, variables[i].name);
                    check_sensitive_info_cached(code, variables[i].name);
                    check_encryption_strength(code, variables[i].name);
                    check_crlf_injection(code, variables[i].name);
                    check_trust_boundary_violation(code, variables[i].name);
                    check_directory_traversal(code, variables[i].name);
                    check_session_fixation(code, variables[i].name);
                    check_risky_crypto(code, variables[i].name);
                    check_credentials_management(code, variables[i].name);
                    check_sql_injection_hibernate(code, variables[i].name);
                    check_improper_resource_shutdown(code, variables[i].name);
                }
            }
        }
        token = strtok(NULL, " \n\t{};");
    }
}

void analyze_code(char *code, int line_number, char *filename) {
    char **stack = (char **)malloc(MAX_CODE * sizeof(char *));  // 포인터 배열로 수정
    for (int i = 0; i < MAX_CODE; i++) {
        stack[i] = (char *)malloc(MAX_CODE * sizeof(char));
    }
    int stack_index = 0;
    int code_index = 0;

    while (code[code_index] != '\0') {
        if (code[code_index] == '{') {
            if (stack_index < MAX_CODE) {
                stack[stack_index][0] = '\0';
                strncat(stack[stack_index], code + code_index + 1, MAX_CODE - 1);
                stack_index++;
            }
        } else if (code[code_index] == '}') {
            if (stack_index > 0) {
                stack_index--;
                analyze_code_block(stack[stack_index], filename);
                stack[stack_index][0] = '\0';
            }
        } else {
            if (stack_index > 0) {
                strncat(stack[stack_index - 1], code + code_index, 1);
            }
        }
        code_index++;
    }

    for (int i = 0; i < MAX_CODE; i++) {
        free(stack[i]);
    }
    free(stack);
}
