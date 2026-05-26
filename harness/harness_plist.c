#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <plist/plist.h>

extern unsigned char *base64decode(const char *buf, size_t *size);

static void usage(const char *prog)
{
    fprintf(stderr, "Usage: %s <mode> <input-file>\n", prog);
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  -b64,  --base64     Decode string value at key 'Data' with base64decode()\n");
    fprintf(stderr, "  -bin,  --binary     Convert string value at key 'UnicodeStr' to binary plist\n");
    fprintf(stderr, "  -xml,  --to-xml     Parse plist_from_memory() and convert to XML\n");
    fprintf(stderr, "  -json, --from-json  Parse JSON plist and convert to XML\n");
}

static int read_file(const char *filename, char **out, uint32_t *out_len)
{
    FILE *fp;
    long size;
    char *buffer;
    size_t nread;

    *out = NULL;
    *out_len = 0;

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        perror("fopen");
        return 1;
    }

    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(fp);
        return 1;
    }

    size = ftell(fp);
    if (size < 0) {
        perror("ftell");
        fclose(fp);
        return 1;
    }

    if ((unsigned long)size > UINT32_MAX) {
        fprintf(stderr, "Input too large for libplist uint32_t length APIs: %ld bytes\n", size);
        fclose(fp);
        return 1;
    }

    if (fseek(fp, 0, SEEK_SET) != 0) {
        perror("fseek");
        fclose(fp);
        return 1;
    }

    buffer = (char *)malloc((size_t)size + 1);
    if (buffer == NULL) {
        perror("malloc");
        fclose(fp);
        return 1;
    }

    nread = fread(buffer, 1, (size_t)size, fp);
    if (nread != (size_t)size) {
        fprintf(stderr, "fread failed: read %zu bytes, expected %ld\n", nread, size);
        free(buffer);
        fclose(fp);
        return 1;
    }

    buffer[size] = '\0';
    fclose(fp);

    *out = buffer;
    *out_len = (uint32_t)size;
    return 0;
}

static int run_base64(const char *filename)
{
    char *buffer = NULL;
    uint32_t length = 0;
    plist_t plist = NULL;
    plist_t data_node;
    char *b64_string = NULL;
    unsigned char *decoded;
    size_t decoded_size;
    size_t i;

    if (read_file(filename, &buffer, &length) != 0)
        return 1;

    plist_from_xml(buffer, length, &plist);
    free(buffer);

    if (plist == NULL) {
        fprintf(stderr, "Failed to parse plist\n");
        return 1;
    }

    data_node = plist_dict_get_item(plist, "Data");
    if ((data_node == NULL) || (plist_get_node_type(data_node) != PLIST_STRING)) {
        fprintf(stderr, "No string data found under key 'Data'\n");
        plist_free(plist);
        return 1;
    }

    plist_get_string_val(data_node, &b64_string);
    if (b64_string == NULL) {
        fprintf(stderr, "Failed to get string value\n");
        plist_free(plist);
        return 1;
    }

    decoded_size = strlen(b64_string);
    decoded = base64decode(b64_string, &decoded_size);
    plist_mem_free(b64_string);

    if (decoded == NULL) {
        fprintf(stderr, "Base64 decode failed\n");
        plist_free(plist);
        return 1;
    }

    printf("Decoded %zu bytes:\n", decoded_size);
    for (i = 0; i < decoded_size; i++)
        printf("%02x ", decoded[i]);
    printf("\n");

    free(decoded);
    plist_free(plist);
    return 0;
}

static int run_binary(const char *filename)
{
    char *buffer = NULL;
    uint32_t length = 0;
    plist_t plist = NULL;
    plist_t str_node;
    plist_t tmp_plist;
    char *str_val = NULL;
    char *plist_bin = NULL;
    uint32_t bin_len = 0;
    plist_err_t err;

    if (read_file(filename, &buffer, &length) != 0)
        return 1;

    plist_from_xml(buffer, length, &plist);
    free(buffer);

    if (plist == NULL) {
        fprintf(stderr, "Failed to parse plist\n");
        return 1;
    }

    str_node = plist_dict_get_item(plist, "UnicodeStr");
    if ((str_node == NULL) || (plist_get_node_type(str_node) != PLIST_STRING)) {
        fprintf(stderr, "No string found under key 'UnicodeStr'\n");
        plist_free(plist);
        return 1;
    }

    plist_get_string_val(str_node, &str_val);
    if (str_val == NULL) {
        fprintf(stderr, "Failed to get string value\n");
        plist_free(plist);
        return 1;
    }

    tmp_plist = plist_new_dict();
    plist_dict_set_item(tmp_plist, "Test", plist_new_string(str_val));
    plist_mem_free(str_val);

    err = plist_to_bin(tmp_plist, &plist_bin, &bin_len);
    if ((err != PLIST_ERR_SUCCESS) || (plist_bin == NULL)) {
        fprintf(stderr, "plist_to_bin failed: %d\n", err);
        plist_free(tmp_plist);
        plist_free(plist);
        return 1;
    }

    printf("Binary plist generated, length: %u\n", bin_len);

    plist_mem_free(plist_bin);
    plist_free(tmp_plist);
    plist_free(plist);
    return 0;
}

static int run_to_xml(const char *filename)
{
    char *buffer = NULL;
    uint32_t length = 0;
    plist_t root = NULL;
    plist_format_t format = PLIST_FORMAT_NONE;
    plist_err_t err;
    char *xml = NULL;
    uint32_t xml_len = 0;

    if (read_file(filename, &buffer, &length) != 0)
        return 1;

    err = plist_from_memory(buffer, length, &root, &format);
    free(buffer);

    if ((err != PLIST_ERR_SUCCESS) || (root == NULL)) {
        fprintf(stderr, "plist_from_memory() failed: %d\n", err);
        return 1;
    }

    printf("Parsed plist successfully! Detected format: %d\n", format);

    err = plist_to_xml(root, &xml, &xml_len);
    if ((err != PLIST_ERR_SUCCESS) || (xml == NULL)) {
        fprintf(stderr, "plist_to_xml() failed: %d\n", err);
        plist_free(root);
        return 1;
    }

    printf("=== Converted to XML ===\n%s\n", xml);

    plist_mem_free(xml);
    plist_free(root);
    return 0;
}

static int run_from_json(const char *filename)
{
    char *buffer = NULL;
    uint32_t length = 0;
    plist_t root = NULL;
    plist_err_t err;
    char *xml = NULL;
    uint32_t xml_len = 0;

    if (read_file(filename, &buffer, &length) != 0)
        return 1;

    err = plist_from_json(buffer, length, &root);
    free(buffer);

    if ((err != PLIST_ERR_SUCCESS) || (root == NULL)) {
        fprintf(stderr, "plist_from_json() failed: %d\n", err);
        return 1;
    }

    printf("Parsed JSON plist successfully!\n");

    err = plist_to_xml(root, &xml, &xml_len);
    if ((err != PLIST_ERR_SUCCESS) || (xml == NULL)) {
        fprintf(stderr, "plist_to_xml() failed: %d\n", err);
        plist_free(root);
        return 1;
    }

    printf("\n=== Converted to XML ===\n%s\n", xml);

    plist_mem_free(xml);
    plist_free(root);
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode;
    const char *filename;

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    mode = argv[1];
    filename = argv[2];

    if ((strcmp(mode, "-b64") == 0) || (strcmp(mode, "--base64") == 0))
        return run_base64(filename);

    if ((strcmp(mode, "-bin") == 0) || (strcmp(mode, "--binary") == 0))
        return run_binary(filename);

    if ((strcmp(mode, "-xml") == 0) || (strcmp(mode, "--to-xml") == 0))
        return run_to_xml(filename);

    if ((strcmp(mode, "-json") == 0) || (strcmp(mode, "--from-json") == 0))
        return run_from_json(filename);

    usage(argv[0]);
    return 1;
}
