#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VAULT_FILE ".vault"
#define MAX_LINE 1024

void cmd_init() {
    FILE *f = fopen(VAULT_FILE, "a");
    if (!f) {
        perror("Failed to initialize vault");
        exit(1);
    }
    fclose(f);
    printf("Initialized vault in %s\n", VAULT_FILE);
}

void cmd_add(const char *service, const char *username, const char *password) {
    FILE *f = fopen(VAULT_FILE, "a");
    if (!f) {
        perror("Failed to open vault");
        exit(1);
    }
    fprintf(f, "%s %s %s\n", service, username, password);
    fclose(f);
    printf("Added password for %s\n", service);
}

void cmd_list() {
    FILE *f = fopen(VAULT_FILE, "r");
    if (!f) {
        printf("Vault not initialized. Run 'vault init' first.\n");
        return;
    }

    char line[MAX_LINE];
    char service[MAX_LINE], username[MAX_LINE], password[MAX_LINE];
    int count = 0;

    printf("Stored services:\n");
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%s %s %s", service, username, password) == 3) {
            printf("- %s\n", service);
            count++;
        }
    }
    if (count == 0) {
        printf("(empty)\n");
    }
    fclose(f);
}

void cmd_get(const char *target_service) {
    FILE *f = fopen(VAULT_FILE, "r");
    if (!f) {
        printf("Vault not initialized.\n");
        return;
    }

    char line[MAX_LINE];
    char service[MAX_LINE], username[MAX_LINE], password[MAX_LINE];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%s %s %s", service, username, password) == 3) {
            if (strcmp(service, target_service) == 0) {
                printf("Service: %s\n", service);
                printf("Username: %s\n", username);
                printf("Password: %s\n", password);
                found = 1;
                break;
            }
        }
    }
    if (!found) {
        printf("No entry found for service: %s\n", target_service);
    }
    fclose(f);
}

void cmd_delete(const char *target_service) {
    FILE *f = fopen(VAULT_FILE, "r");
    if (!f) {
        printf("Vault not initialized.\n");
        return;
    }

    FILE *temp = fopen(".vault.tmp", "w");
    if (!temp) {
        perror("Failed to create temporary file");
        fclose(f);
        exit(1);
    }

    char line[MAX_LINE];
    char service[MAX_LINE], username[MAX_LINE], password[MAX_LINE];
    int deleted = 0;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%s %s %s", service, username, password) == 3) {
            if (strcmp(service, target_service) == 0) {
                deleted = 1;
                continue;
            }
        }
        fputs(line, temp);
    }

    fclose(f);
    fclose(temp);

    if (deleted) {
        rename(".vault.tmp", VAULT_FILE);
        printf("Deleted entry for %s\n", target_service);
    } else {
        remove(".vault.tmp");
        printf("No entry found for service: %s\n", target_service);
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: vault <command> [args]\n");
        fprintf(stderr, "Commands: init, add, list, get, delete\n");
        return 1;
    }

    char *command = argv[1];

    if (strcmp(command, "init") == 0) {
        cmd_init();
    } else if (strcmp(command, "add") == 0) {
        if (argc != 5) {
            fprintf(stderr, "Usage: vault add <service> <username> <password>\n");
            return 1;
        }
        cmd_add(argv[2], argv[3], argv[4]);
    } else if (strcmp(command, "list") == 0) {
        cmd_list();
    } else if (strcmp(command, "get") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: vault get <service>\n");
            return 1;
        }
        cmd_get(argv[2]);
    } else if (strcmp(command, "delete") == 0) {
        if (argc != 3) {
            fprintf(stderr, "Usage: vault delete <service>\n");
            return 1;
        }
        cmd_delete(argv[2]);
    } else {
        fprintf(stderr, "Unknown command: %s\n", command);
        return 1;
    }

    return 0;
}
