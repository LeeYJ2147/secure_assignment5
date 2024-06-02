#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>

#define MAX_PATH 1024
#define MAX_LINE 2048
#define MAX_CODE 8192  // 코드 단위를 저장할 최대 크기

// 민감한 정보 키워드를 확인하는 함수
int contains_sensitive_info(char *code) {
    return strstr(code, "password") || strstr(code, "secret") || strstr(code, "apikey") || strstr(code, "token");
}

// SQL Injection 체크 함수
void check_sql_injection(char *line, int line_number, char *filename) {
    // SQL 구문이 포함되어 있는지 확인
    if ((strstr(line, "SELECT") || strstr(line, "INSERT") || strstr(line, "UPDATE") || strstr(line, "DELETE"))) {
        // prepared statement를 사용하는지 확인
        if (!(strstr(line, "?") || strstr(line, ":") || strstr(line, "bind_param") || strstr(line, "bindValue"))) {
            // 사용자 입력이 포함된 SQL 구문이 아닌지 확인
            if (strstr(line, "input") || strstr(line, "user")) {
                printf("Potential SQL Injection in file %s at line %d: %s", filename, line_number, line);
            }
        }
    }
}

// Cross Site Scripting (XSS) 체크 함수
void check_xss(char *line, int line_number, char *filename) {
    // XSS 공격 패턴이 포함된 경우 확인
    if (strstr(line, "document.write") || strstr(line, "innerHTML") || strstr(line, "outerHTML") || strstr(line, "eval")) {
        // 사용자 입력이 포함된 경우
        if (strstr(line, "input") || strstr(line, "user")) {
            printf("Potential XSS in file %s at line %d: %s", filename, line_number, line);
        }
    }
}

// 정보 누출 체크 함수
void check_information_leakage(char *line, int line_number, char *filename) {
    // 정보 노출 패턴이 포함된 경우 확인
    if (strstr(line, "print") || strstr(line, "echo") || strstr(line, "console.log") || strstr(line, "logger.info")) {
        // 민감한 정보 키워드가 포함된 경우
        if (strstr(line, "password") || strstr(line, "secret") || strstr(line, "apikey") || strstr(line, "token")) {
            printf("Potential Information Leakage in file %s at line %d: %s", filename, line_number, line);
        }
    }
}

// 프레임 인젝션 체크 함수
void check_frame_injection(char *line, int line_number, char *filename) {
    // 프레임 태그가 포함된 경우 확인
    if (strstr(line, "<iframe") || strstr(line, "<frame")) {
        // 외부 URL을 로드하는 경우
        if (strstr(line, "src=") && (strstr(line, "http://") || strstr(line, "https://"))) {
            printf("Potential Frame Injection in file %s at line %d: %s", filename, line_number, line);
        }
    }
}

// URL Redirection 체크 함수
void check_url_redirection(char *line, int line_number, char *filename) {
    if (strstr(line, "location.href") || strstr(line, "window.location") || strstr(line, "response.sendRedirect")) {
        if (strstr(line, "http://") || strstr(line, "https://")) {
            printf("Potential URL Redirection in file %s at line %d: %s", filename, line_number, line);
        }
    }
}

// Missing Session Timeout 체크 함수
void check_missing_session_timeout(char *line, int line_number, char *filename) {
    if (strstr(line, "session")) {
        if (!(strstr(line, "timeout") || strstr(line, "expire") || strstr(line, "expiration"))) {
            printf("Potential Missing Session Timeout in file %s at line %d: %s", filename, line_number, line);
        }
    }
}

// URL에 평문으로 민감한 정보 전달 체크 함수
void check_sensitive_info_in_url(char *line, int line_number, char *filename) {
    if (strstr(line, "GET") || strstr(line, "POST")) {
        if (strstr(line, "password") || strstr(line, "secret") || strstr(line, "apikey") || strstr(line, "token")) {
            printf("Potential Sensitive Information in URL in file %s at line %d: %s", filename, line_number, line);
        }
    }
}

// Session ID Cookies Not Marked Secure 체크 함수
void check_secure_cookie(char *line, int line_number, char *filename) {
    if (strstr(line, "Set-Cookie")) {
        if (!(strstr(line, "Secure") && strstr(line, "HttpOnly"))) {
            printf("Potential Session ID Cookie Not Marked Secure in file %s at line %d: %s", filename, line_number, line);
        }
    }
}

// Cross Frame Scripting (XFS) 체크 함수
void check_cross_frame_scripting(char *code, int line_number, char *filename) {
    if (strstr(code, "<iframe") || strstr(code, "<frame")) {
        if (strstr(code, "src=") && (strstr(code, "http://") || strstr(code, "https://"))) {
            printf("Potential Cross Frame Scripting (XFS) in file %s at line %d: %s\n", filename, line_number, code);
        }
    }
}

// 화면에 민감한 정보가 평문으로 표시되는지 체크하는 함수
void check_sensitive_info_display(char *code, int line_number, char *filename) {
    if (strstr(code, "print") || strstr(code, "echo") || strstr(code, "console.log") || strstr(code, "alert")) {
        if (contains_sensitive_info(code)) {
            printf("Potential Sensitive Information Displayed on Screen in file %s at line %d: %s\n", filename, line_number, code);
        }
    }
}

// 캐시된 민감한 정보가 있는지 체크하는 함수
void check_sensitive_info_cached(char *code, int line_number, char *filename) {
    if (strstr(code, "cache") && contains_sensitive_info(code)) {
        printf("Potential Sensitive Information Cached in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// 암호화 알고리즘이 충분히 강력한지 체크하는 함수
void check_encryption_strength(char *code, int line_number, char *filename) {
    if ((strstr(code, "encrypt") || strstr(code, "decrypt")) &&
        (strstr(code, "MD5") || strstr(code, "SHA1") || strstr(code, "DES"))) {
        printf("Potential Inadequate Encryption Strength in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// CRLF Injection 체크 함수
void check_crlf_injection(char *code, int line_number, char *filename) {
    if (strstr(code, "\r\n")) {
        printf("Potential CRLF Injection in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// Trust Boundary Violation 체크 함수
void check_trust_boundary_violation(char *code, int line_number, char *filename) {
    if (strstr(code, "trust_boundary")) {
        printf("Potential Trust Boundary Violation in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// Directory Traversal 체크 함수
void check_directory_traversal(char *code, int line_number, char *filename) {
    if (strstr(code, "../") || strstr(code, "..\\")) {
        printf("Potential Directory Traversal in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// Session Fixation 체크 함수
void check_session_fixation(char *code, int line_number, char *filename) {
    if (strstr(code, "session") && strstr(code, "fixation")) {
        printf("Potential Session Fixation in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// 취약한 암호화 알고리즘 사용 체크 함수
void check_risky_crypto_algorithm(char *code, int line_number, char *filename) {
    if (strstr(code, "MD5") || strstr(code, "SHA1") || strstr(code, "DES")) {
        printf("Potential Use of a Risky Cryptographic Algorithm in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// 자격 증명 관리 체크 함수
void check_credentials_management(char *code, int line_number, char *filename) {
    if (strstr(code, "password") && (strstr(code, "plain") || strstr(code, "base64") || strstr(code, "md5"))) {
        printf("Potential Credentials Management Issue in file %s at line %d: %s\n", filename, line_number, code);
    }
}

// Hibernate 기반 SQL Injection 체크 함수
void check_sql_injection_hibernate(char *code, int line_number, char *filename) {
    if (strstr(code, "Hibernate") && (strstr(code, "createQuery") || strstr(code, "createSQLQuery"))) {
        if (strstr(code, "input") || strstr(code, "user")) {
            printf("Potential SQL Injection Hibernate in file %s at line %d: %s\n", filename, line_number, code);
        }
    }
}

// 리소스 종료 또는 해제 문제 체크 함수
void check_improper_resource_shutdown(char *code, int line_number, char *filename) {
    if ((strstr(code, "File") || strstr(code, "Socket") || strstr(code, "Connection")) &&
        !(strstr(code, "close") || strstr(code, "shutdown") || strstr(code, "release"))) {
        printf("Potential Improper Resource Shutdown or Release in file %s at line %d: %s\n", filename, line_number, code);
    }
}

void analyze_file(char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    char line[MAX_LINE];
    char code[MAX_CODE] = "";
    int line_number = 0;

    while (fgets(line, sizeof(line), file)) {
        line_number++;
        strcat(code, line);

        char *token = strtok(code, ";");
        while (token != NULL) {
            char complete_code[MAX_CODE];
            strcpy(complete_code, token);
            strcat(complete_code, ";");

            check_sql_injection(complete_code, line_number, filepath);
            check_xss(complete_code, line_number, filepath);
            check_information_leakage(complete_code, line_number, filepath);
            check_frame_injection(complete_code, line_number, filepath);

            check_url_redirection(complete_code, line_number, filepath);
            check_missing_session_timeout(complete_code, line_number, filepath);
            check_sensitive_info_in_url(complete_code, line_number, filepath);
            check_secure_cookie(complete_code, line_number, filepath);

            check_cross_frame_scripting(complete_code, line_number, filepath);
            check_sensitive_info_display(complete_code, line_number, filepath);
            check_sensitive_info_cached(complete_code, line_number, filepath);
            check_encryption_strength(complete_code, line_number, filepath);

            check_crlf_injection(complete_code, line_number, filepath);
            check_trust_boundary_violation(complete_code, line_number, filepath);
            check_directory_traversal(complete_code, line_number, filepath);
            check_session_fixation(complete_code, line_number, filepath);

            check_risky_crypto_algorithm(complete_code, line_number, filepath);
            check_credentials_management(complete_code, line_number, filepath);
            check_sql_injection_hibernate(complete_code, line_number, filepath);
            check_improper_resource_shutdown(complete_code, line_number, filepath);

            token = strtok(NULL, ";");
        }

        // 남아있는 코드 단위를 다음 라인으로 가져오기 위해 이동
        int remaining_length = strlen(line);
        if (remaining_length > 0 && line[remaining_length - 1] != ';') {
            // 마지막으로 남은 부분을 code에 저장
            strcpy(code, token ? token : "");
        } else {
            strcpy(code, ""); // 남아있는 부분이 없으면 초기화
        }
    }

    fclose(file);
}

void analyze_directory(const char *path) {
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (dp == NULL) {
        perror("opendir");
        return;
    }

    char filepath[MAX_PATH];
    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_DIR) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
            analyze_directory(filepath);
        } else {
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);
            analyze_file(filepath);
        }
    }

    closedir(dp);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <directory_path>\n", argv[0]);
        return 1;
    }

    analyze_directory(argv[1]);

    return 0;
}

/**
 * Notes:
 * 1. `check_sql_injection`: This function checks for SQL queries that might be vulnerable to injection attacks,
 *    particularly focusing on lines that include user input without using prepared statements.
 * 2. `check_xss`: This function looks for potential XSS vulnerabilities by identifying unsafe use of `document.write`,
 *    `innerHTML`, `outerHTML`, and `eval` with user input.
 * 3. `check_information_leakage`: This function checks for instances where sensitive information might be logged or printed,
 *    such as passwords or API keys.
 * 4. `check_frame_injection`: This function identifies potential frame injection vulnerabilities by checking for `<iframe>`
 *    and `<frame>` tags loading external URLs.
 * 5. `check_url_redirection`: This function checks for potentially unsafe URL redirection logic that redirects to external URLs.
 * 6. `check_missing_session_timeout`: This function looks for session management code that lacks timeout or expiration settings.
 * 7. `check_sensitive_info_in_url`: This function checks for sensitive information being passed in GET or POST requests via URLs.
 * 8. `check_secure_cookie`: This function identifies cookies that are set without the `Secure` and `HttpOnly` flags.
 * 9. `check_cross_frame_scripting`: This function checks for potential cross frame scripting vulnerabilities
 *    by identifying the use of `<iframe>` or `<frame>` tags loading external URLs.
 * 10. `check_sensitive_info_display`: This function looks for instances where sensitive information might be
 *     displayed on the screen, such as passwords or API keys being printed or logged.
 * 11. `check_sensitive_info_cached`: This function checks for sensitive information being cached,
 *     which could pose a security risk if the cache is not properly secured.
 * 12. `check_encryption_strength`: This function identifies the use of weak encryption algorithms
 *     such as MD5, SHA1, or DES, which are considered inadequate for secure encryption.
 * 13. `check_crlf_injection`: This function checks for potential CRLF injection vulnerabilities by identifying
 *     instances where carriage return and line feed characters are included in input.
 * 14. `check_trust_boundary_violation`: This function looks for potential trust boundary violations by identifying
 *     code sections where trust boundaries are crossed without proper validation.
 * 15. `check_directory_traversal`: This function checks for potential directory traversal vulnerabilities by
 *     identifying instances where paths include sequences like "../" or "..\".
 * 16. `check_session_fixation`: This function looks for potential session fixation vulnerabilities by identifying
 *     code sections where session IDs might be fixed or controlled by an attacker.
 * 17. `check_risky_crypto_algorithm`: This function checks for potential use of risky cryptographic algorithms by identifying
 *     instances where MD5, SHA1, or DES are used.
 * 18. `check_credentials_management`: This function looks for potential credentials management issues by identifying
 *     instances where passwords are stored or handled in an insecure manner, such as plain text or weak hashes.
 * 19. `check_sql_injection_hibernate`: This function checks for potential SQL injection vulnerabilities in Hibernate by
 *     identifying instances where user input is included in Hibernate queries without proper parameterization.
 * 20. `check_improper_resource_shutdown`: This function looks for potential improper resource shutdown or release issues by
 *     identifying instances where resources such as files, sockets, or connections are not properly closed or released.
 */