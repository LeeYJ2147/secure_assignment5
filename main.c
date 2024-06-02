#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include "security_checks.h"

#define MAX_PATH 1024
#define MAX_CODE 8192

extern SecurityIssue issues[MAX_VIOLATIONS];
extern int issue_count;
extern Variable variables[MAX_VIOLATIONS];
extern int variable_count;

void analyze_file(char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("fopen");
        return;
    }

    printf("\tAnalyzing file: %s\n", filepath); // 현재 파일명 출력

    char line[MAX_LINE];
    char code[MAX_CODE*10] = "";
    int line_number = 0;

    issue_count = 0;  // 파일 분석 시작 전에 issues 초기화
    variable_count = 0;  // 파일 분석 시작 전에 variables 초기화

    while (fgets(line, sizeof(line), file)) {
        line_number++;
        strcat(code, line);
    }

    fclose(file);
    //printf("%s\n", code);
    analyze_code(code, line_number, filepath);  // 파일 전체 내용을 분석

    // 파일 분석 후 unresolved issues 출력
    int is_all_cleared = 1;
    for (int i = 0; i < issue_count; i++) {
        if (!issues[i].resolved) {
            if (is_all_cleared) {
                printf("\t\t❌ Issues found in file: %s\n", filepath);
                is_all_cleared = 0;
            }
            printf("\t\t- Unresolved issue:\n\t\t\tvariable: %s,\n\t\t\tviolation: %s\n",
                issues[i].variable_name,
                violation_strings[issues[i].violation]);
        }
    }
    if (is_all_cleared) {
        printf("\t\t✅ No issues found in file: %s... Good!!\n", filepath);
    }
}

void analyze_directory(const char *path) {
    struct dirent *entry;
    DIR *dp = opendir(path);

    if (dp == NULL) {
        perror("opendir");
        return;
    }

    printf("\nAnalyzing directory: %s\n", path); // 현재 경로 출력

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
