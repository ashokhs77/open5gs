/*
 * Copyright (C) 2026 Lekha Wireless
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "unauthorized-audit.h"

#define DEFAULT_UNAUTHORIZED_ATTACH_CSV \
    "/open5gs/install/var/log/open5gs/unauthorized_attach_attempts.csv"
#define DEFAULT_UNAUTHORIZED_ATTACH_MAX_BYTES (10 * 1024 * 1024)
#define REJECT_AUDIT_CSV_HEADER \
    "date,time,imei,imsi,reject_message,reject_cause,reject_reason\n"

static const char *emm_cause_name(ogs_nas_emm_cause_t cause)
{
    switch (cause) {
    case OGS_NAS_EMM_CAUSE_IMSI_UNKNOWN_IN_HSS:
        return "IMSI unknown in HSS";
    case OGS_NAS_EMM_CAUSE_ILLEGAL_UE:
        return "Illegal UE";
    case OGS_NAS_EMM_CAUSE_IMSI_UNKNOWN_IN_VLR:
        return "IMSI unknown in VLR";
    case OGS_NAS_EMM_CAUSE_IMEI_NOT_ACCEPTED:
        return "IMEI not accepted";
    case OGS_NAS_EMM_CAUSE_ILLEGAL_ME:
        return "Illegal ME";
    case OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED:
        return "EPS services not allowed";
    case OGS_NAS_EMM_CAUSE_EPS_SERVICES_AND_NON_EPS_SERVICES_NOT_ALLOWED:
        return "EPS services and non-EPS services not allowed";
    case OGS_NAS_EMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK:
        return "UE identity cannot be derived by the network";
    case OGS_NAS_EMM_CAUSE_IMPLICITLY_DETACHED:
        return "Implicitly detached";
    case OGS_NAS_EMM_CAUSE_PLMN_NOT_ALLOWED:
        return "PLMN not allowed";
    case OGS_NAS_EMM_CAUSE_TRACKING_AREA_NOT_ALLOWED:
        return "Tracking area not allowed";
    case OGS_NAS_EMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA:
        return "Roaming not allowed in this tracking area";
    case OGS_NAS_EMM_CAUSE_EPS_SERVICES_NOT_ALLOWED_IN_THIS_PLMN:
        return "EPS services not allowed in this PLMN";
    case OGS_NAS_EMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA:
        return "No suitable cells in tracking area";
    case OGS_NAS_EMM_CAUSE_MSC_TEMPORARILY_NOT_REACHABLE:
        return "MSC temporarily not reachable";
    case OGS_NAS_EMM_CAUSE_NETWORK_FAILURE:
        return "Network failure";
    case OGS_NAS_EMM_CAUSE_CS_DOMAIN_NOT_AVAILABLE:
        return "CS domain not available";
    case OGS_NAS_EMM_CAUSE_ESM_FAILURE:
        return "ESM failure";
    case OGS_NAS_EMM_CAUSE_MAC_FAILURE:
        return "MAC failure";
    case OGS_NAS_EMM_CAUSE_SYNCH_FAILURE:
        return "Synchronization failure";
    case OGS_NAS_EMM_CAUSE_CONGESTION:
        return "Congestion";
    case OGS_NAS_EMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH:
        return "UE security capabilities mismatch";
    case OGS_NAS_EMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED:
        return "Security mode rejected unspecified";
    case 25: /* 3GPP TS 24.301: NOT_AUTHORIZED_FOR_THIS_CSG */
        return "Not authorized for this CSG";
    case OGS_NAS_EMM_CAUSE_NON_EPS_AUTHENTICATION_UNACCEPTABLE:
        return "Non-EPS authentication unacceptable";
    case 31: /* 3GPP TS 24.301: REDIRECTION_TO_5GCN_REQUIRED */
        return "Redirection to 5GCN required";
    case OGS_NAS_EMM_CAUSE_REQUESTED_SERVICE_OPTION_NOT_AUTHORIZED_IN_THIS_PLMN:
        return "Requested service option not authorized in this PLMN";
    case 36: /* 3GPP TS 24.301: IAB_NODE_OPERATION_NOT_AUTHORIZED */
        return "IAB-node operation not authorized";
    case OGS_NAS_EMM_CAUSE_CS_SERVICE_TEMPORARILY_NOT_AVAILABLE:
        return "CS service temporarily not available";
    case OGS_NAS_EMM_CAUSE_NO_EPS_BEARER_CONTEXT_ACTIVATED:
        return "No EPS bearer context activated";
    case OGS_NAS_EMM_CAUSE_SEVERE_NETWORK_FAILURE:
        return "Severe network failure";
    case 78: /* 3GPP TS 24.301: PLMN_NOT_ALLOWED_AT_PRESENT_LOCATION */
        return "PLMN not allowed to operate at the present UE location";
    case 80: /* 3GPP TS 24.301: DISASTER_ROAMING_NOT_ALLOWED */
        return "Disaster roaming for the determined PLMN with disaster condition not allowed";
    case 83: /* 3GPP TS 24.301: S_AND_F_FEEDER_LINK_UNAVAILABLE */
        return "Procedure cannot be completed due to unavailable feeder link while MME is operating in S&F mode";
    case OGS_NAS_EMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE:
        return "Semantically incorrect message";
    case OGS_NAS_EMM_CAUSE_INVALID_MANDATORY_INFORMATION:
        return "Invalid mandatory information";
    case OGS_NAS_EMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "Message type non-existent or not implemented";
    case OGS_NAS_EMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE:
        return "Message type not compatible with protocol state";
    case OGS_NAS_EMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "Information element non-existent or not implemented";
    case OGS_NAS_EMM_CAUSE_CONDITIONAL_IE_ERROR:
        return "Conditional IE error";
    case OGS_NAS_EMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_PROTOCOL_STATE:
        return "Message not compatible with protocol state";
    case OGS_NAS_EMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED:
        return "Protocol error unspecified";
    default:
        /*
         * Preserve the numeric cause in the CSV even when a newer 3GPP
         * release or vendor extension introduces a value unknown to this
         * Open5GS revision.
         */
        return "Unassigned or future EMM cause";
    }
}

static bool digits_only(const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    if (!p || !*p)
        return false;

    while (*p) {
        if (*p < '0' || *p > '9')
            return false;
        p++;
    }

    return true;
}

static int write_all(int fd, const char *buffer, size_t length)
{
    size_t written = 0;

    while (written < length) {
        ssize_t rv = write(fd, buffer + written, length - written);
        if (rv < 0) {
            if (errno == EINTR)
                continue;
            return OGS_ERROR;
        }
        if (rv == 0) {
            errno = EIO;
            return OGS_ERROR;
        }
        written += rv;
    }

    return OGS_OK;
}

static int imei_from_imeisv(
        const char *imeisv_bcd, char *imei_bcd, size_t imei_bcd_size)
{
    int i, sum = 0;

    ogs_assert(imei_bcd);

    if (!digits_only(imeisv_bcd) ||
        strlen(imeisv_bcd) != OGS_MAX_IMEISV_BCD_LEN ||
        imei_bcd_size < OGS_MAX_IMSI_BCD_LEN + 1) {
        return OGS_ERROR;
    }

    memcpy(imei_bcd, imeisv_bcd, OGS_MAX_IMSI_BCD_LEN - 1);
    for (i = 0; i < OGS_MAX_IMSI_BCD_LEN - 1; i++) {
        int digit = imei_bcd[i] - '0';
        if (i & 1) {
            digit *= 2;
            if (digit > 9)
                digit -= 9;
        }
        sum += digit;
    }
    imei_bcd[OGS_MAX_IMSI_BCD_LEN - 1] =
        '0' + ((10 - (sum % 10)) % 10);
    imei_bcd[OGS_MAX_IMSI_BCD_LEN] = '\0';

    return OGS_OK;
}

typedef enum audit_csv_schema_e {
    AUDIT_CSV_CURRENT,
    AUDIT_CSV_LEGACY_FOUR_COLUMNS,
    AUDIT_CSV_LEGACY_CAUSE_ONLY,
    AUDIT_CSV_LEGACY_ATTACH_REJECT,
} audit_csv_schema_t;

static int migrate_previous_row(
        int destination, audit_csv_schema_t schema, char *line)
{
    char date[16], time[16], imei[32], imsi[32];
    char cause[16], reason[160], migrated[320];
    unsigned long cause_value;
    int fields, length;

    if (schema == AUDIT_CSV_CURRENT)
        return write_all(destination, line, strlen(line));

    date[0] = time[0] = imei[0] = imsi[0] = '\0';
    cause[0] = reason[0] = '\0';

    if (schema == AUDIT_CSV_LEGACY_FOUR_COLUMNS) {
        fields = sscanf(line, "%15[^,],%15[^,],%31[^,],%31[^\n]",
                date, time, imei, imsi);
        if (fields != 4)
            return OGS_ERROR;
        length = snprintf(migrated, sizeof(migrated),
                "%s,%s,%s,%s,Attach Reject,N/A,Legacy row without reject cause\n",
                date, time, imei, imsi);
    } else if (schema == AUDIT_CSV_LEGACY_CAUSE_ONLY) {
        fields = sscanf(line, "%15[^,],%15[^,],%31[^,],%31[^,],%15[^\n]",
                date, time, imei, imsi, cause);
        if (fields != 5)
            return OGS_ERROR;
        cause_value = strtoul(cause, NULL, 10);
        length = snprintf(migrated, sizeof(migrated),
                "%s,%s,%s,%s,Attach Reject,%s,%s\n",
                date, time, imei, imsi, cause,
                emm_cause_name((ogs_nas_emm_cause_t)cause_value));
    } else {
        fields = sscanf(line,
                "%15[^,],%15[^,],%31[^,],%31[^,],%15[^,],%159[^\n]",
                date, time, imei, imsi, cause, reason);
        if (fields != 6)
            return OGS_ERROR;
        length = snprintf(migrated, sizeof(migrated),
                "%s,%s,%s,%s,Attach Reject,%s,%s\n",
                date, time, imei, imsi, cause, reason);
    }

    if (length < 0 || (size_t)length >= sizeof(migrated))
        return OGS_ERROR;
    return write_all(destination, migrated, length);
}

static int copy_previous_rows(FILE *source, int destination)
{
    char line[320];
    audit_csv_schema_t schema;

    if (!source)
        return OGS_OK;

    if (!fgets(line, sizeof(line), source))
        return ferror(source) ? OGS_ERROR : OGS_OK;

    if (!strcmp(line, REJECT_AUDIT_CSV_HEADER))
        schema = AUDIT_CSV_CURRENT;
    else if (!strcmp(line, "date,time,imei,imsi\n"))
        schema = AUDIT_CSV_LEGACY_FOUR_COLUMNS;
    else if (!strcmp(line,
                "date,time,imei,imsi,attach_reject_cause\n"))
        schema = AUDIT_CSV_LEGACY_CAUSE_ONLY;
    else if (!strcmp(line,
                "date,time,imei,imsi,attach_reject_cause,attach_reject_reason\n"))
        schema = AUDIT_CSV_LEGACY_ATTACH_REJECT;
    else {
        errno = EINVAL;
        return OGS_ERROR;
    }

    while (fgets(line, sizeof(line), source)) {
        if (migrate_previous_row(destination, schema, line) != OGS_OK)
            return OGS_ERROR;
    }

    if (ferror(source)) {
        errno = EIO;
        return OGS_ERROR;
    }

    return OGS_OK;
}

static const char *audit_path(void)
{
    const char *path = getenv("MME_UNAUTHORIZED_ATTACH_CSV");

    return (path && *path) ? path : DEFAULT_UNAUTHORIZED_ATTACH_CSV;
}

static off_t audit_max_bytes(void)
{
    const char *configured = getenv("MME_UNAUTHORIZED_ATTACH_MAX_BYTES");
    char *end = NULL;
    unsigned long long value;

    if (!configured || !*configured)
        return DEFAULT_UNAUTHORIZED_ATTACH_MAX_BYTES;

    errno = 0;
    value = strtoull(configured, &end, 10);
    if (errno || !end || *end || value > (unsigned long long)LLONG_MAX) {
        ogs_error("Invalid MME_UNAUTHORIZED_ATTACH_MAX_BYTES [%s]",
                configured);
        return DEFAULT_UNAUTHORIZED_ATTACH_MAX_BYTES;
    }
    return (off_t)value;
}

static int replace_audit_csv(
        const mme_ue_t *mme_ue, const char *reject_message,
        int emm_cause, const char *reason_override, bool initialize_only)
{
    const char *path = audit_path();
    const char *imsi = "unknown";
    const char *imei = "unknown";
    const char *reason = reason_override;
    char imei_bcd[OGS_MAX_IMSI_BCD_LEN+1] = "";
    char temp_path[OGS_MAX_FILEPATH_LEN];
    char archive_path[OGS_MAX_FILEPATH_LEN];
    char row[320] = "";
    struct timeval tv;
    struct tm local;
    struct stat source_stat;
    FILE *source = NULL;
    int destination = -1;
    off_t max_bytes = audit_max_bytes();
    bool rotate = false, archived = false;
    int path_length, row_length = 0, rv = OGS_ERROR;

    ogs_gettimeofday(&tv);
    ogs_localtime(tv.tv_sec, &local);

    if (!initialize_only) {
        ogs_assert(mme_ue);
        ogs_assert(reject_message);

        if (digits_only(mme_ue->attach_attempt_imsi_bcd))
            imsi = mme_ue->attach_attempt_imsi_bcd;
        else if (digits_only(mme_ue->imsi_bcd))
            imsi = mme_ue->imsi_bcd;
        if (imei_from_imeisv(mme_ue->imeisv_bcd,
                    imei_bcd, sizeof(imei_bcd)) == OGS_OK)
            imei = imei_bcd;
        if (!reason)
            reason = emm_cause_name((ogs_nas_emm_cause_t)emm_cause);

        if (emm_cause >= 0)
            row_length = snprintf(row, sizeof(row),
                    "%04d-%02d-%02d,%02d:%02d:%02d,%s,%s,%s,%u,%s\n",
                    local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
                    local.tm_hour, local.tm_min, local.tm_sec,
                    imei, imsi, reject_message,
                    (unsigned int)emm_cause, reason);
        else
            row_length = snprintf(row, sizeof(row),
                    "%04d-%02d-%02d,%02d:%02d:%02d,%s,%s,%s,N/A,%s\n",
                    local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
                    local.tm_hour, local.tm_min, local.tm_sec,
                    imei, imsi, reject_message, reason);
        if (row_length < 0 || (size_t)row_length >= sizeof(row)) {
            ogs_error("Cannot format mobility reject CSV row");
            return OGS_ERROR;
        }
    }

    path_length = snprintf(
            temp_path, sizeof(temp_path), "%s.tmp.XXXXXX", path);
    if (path_length < 0 || (size_t)path_length >= sizeof(temp_path)) {
        ogs_error("Attach reject CSV path is too long [%s]", path);
        return OGS_ERROR;
    }

    source = fopen(path, "r");
    if (!source && errno != ENOENT) {
        ogs_error("Cannot read attach reject CSV [%s]: %s",
                path, strerror(errno));
        return OGS_ERROR;
    }

    if (source && !initialize_only && max_bytes > 0 &&
        fstat(fileno(source), &source_stat) == 0 &&
        source_stat.st_size >= max_bytes) {
        rotate = true;
    }

    destination = mkstemp(temp_path);
    if (destination < 0) {
        ogs_error("Cannot create attach reject CSV temporary file [%s]: %s",
                temp_path, strerror(errno));
        if (source)
            fclose(source);
        return OGS_ERROR;
    }
    if (fchmod(destination, 0644) != 0) {
        ogs_error("Cannot set attach reject CSV permissions [%s]: %s",
                temp_path, strerror(errno));
        close(destination);
        if (source)
            fclose(source);
        unlink(temp_path);
        return OGS_ERROR;
    }

    if (write_all(destination,
                REJECT_AUDIT_CSV_HEADER,
                sizeof(REJECT_AUDIT_CSV_HEADER) - 1) != OGS_OK ||
        (!initialize_only && write_all(destination, row, row_length) != OGS_OK) ||
        (!rotate && copy_previous_rows(source, destination) != OGS_OK) ||
        fsync(destination) != 0) {
        ogs_error("Cannot update mobility reject CSV [%s]: %s",
                path, strerror(errno));
        goto cleanup;
    }

    if (source && fclose(source) != 0) {
        source = NULL;
        ogs_error("Cannot close attach reject CSV [%s]: %s",
                path, strerror(errno));
        goto cleanup;
    }
    source = NULL;

    if (close(destination) != 0) {
        destination = -1;
        ogs_error("Cannot close attach reject CSV temporary file [%s]: %s",
                temp_path, strerror(errno));
        goto cleanup;
    }
    destination = -1;

    if (rotate) {
        path_length = snprintf(archive_path, sizeof(archive_path),
                "%s.archive.%lld.%06ld.csv", path,
                (long long)tv.tv_sec, (long)tv.tv_usec);
        if (path_length < 0 ||
            (size_t)path_length >= sizeof(archive_path)) {
            ogs_error("Mobility reject CSV archive path is too long [%s]",
                    path);
            goto cleanup;
        }
        if (rename(path, archive_path) != 0) {
            ogs_error("Cannot rotate mobility reject CSV [%s]: %s",
                    path, strerror(errno));
            goto cleanup;
        }
        archived = true;
    }

    if (rename(temp_path, path) != 0) {
        int saved_errno = errno;
        if (archived && rename(archive_path, path) != 0)
            ogs_error("Cannot restore mobility reject CSV [%s]: %s",
                    path, strerror(errno));
        errno = saved_errno;
        ogs_error("Cannot replace mobility reject CSV [%s]: %s",
                path, strerror(errno));
        goto cleanup;
    }

    if (initialize_only)
        ogs_info("Mobility reject audit ready: CSV[%s] MaxBytes[%lld]",
                path, (long long)max_bytes);
    else if (emm_cause >= 0)
        ogs_warn("Mobility reject recorded: Message[%s] IMSI[%s] IMEI[%s] "
                "Cause[%u:%s] CSV[%s]",
                reject_message, imsi, imei,
                (unsigned int)emm_cause, reason, path);
    else
        ogs_warn("Mobility reject recorded: Message[%s] IMSI[%s] IMEI[%s] "
                "Reason[%s] CSV[%s]",
                reject_message, imsi, imei, reason, path);
    rv = OGS_OK;

cleanup:
    if (source)
        fclose(source);
    if (destination >= 0)
        close(destination);
    if (rv != OGS_OK)
        unlink(temp_path);
    return rv;
}

int mme_unauthorized_audit_init(void)
{
    const char *path = audit_path();
    FILE *source = fopen(path, "r");

    if (source) {
        fclose(source);
    } else if (errno != ENOENT) {
        ogs_error("Cannot inspect mobility reject CSV [%s]: %s",
                path, strerror(errno));
        return OGS_ERROR;
    }

    return replace_audit_csv(NULL, NULL, -1, NULL, true);
}

int mme_unauthorized_audit_append(
        const mme_ue_t *mme_ue, const char *reject_message,
        int emm_cause, const char *reason_override)
{
    return replace_audit_csv(mme_ue, reject_message,
            emm_cause, reason_override, false);
}
