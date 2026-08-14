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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "registration-audit.h"

#define DEFAULT_REGISTRATION_REJECT_CSV \
    "/open5gs/install/var/log/open5gs/unauthorized_registration_attempts.csv"
#define REGISTRATION_REJECT_CSV_HEADER \
    "date,time,imei,imsi,supi_or_suci,registration_reject_cause," \
    "registration_reject_reason\n"

static const char *gmm_cause_name(ogs_nas_5gmm_cause_t cause)
{
    /*
     * 3GPP TS 24.501, table 9.11.3.2.1. Numeric cases are used for causes
     * added after the Open5GS revision pinned by docker_open5gs.
     */
    switch (cause) {
    case OGS_5GMM_CAUSE_ILLEGAL_UE:
        return "Illegal UE";
    case OGS_5GMM_CAUSE_PEI_NOT_ACCEPTED:
        return "PEI not accepted";
    case OGS_5GMM_CAUSE_ILLEGAL_ME:
        return "Illegal ME";
    case OGS_5GMM_CAUSE_5GS_SERVICES_NOT_ALLOWED:
        return "5GS services not allowed";
    case OGS_5GMM_CAUSE_UE_IDENTITY_CANNOT_BE_DERIVED_BY_THE_NETWORK:
        return "UE identity cannot be derived by the network";
    case OGS_5GMM_CAUSE_IMPLICITLY_DE_REGISTERED:
        return "Implicitly de-registered";
    case OGS_5GMM_CAUSE_PLMN_NOT_ALLOWED:
        return "PLMN not allowed";
    case OGS_5GMM_CAUSE_TRACKING_AREA_NOT_ALLOWED:
        return "Tracking area not allowed";
    case OGS_5GMM_CAUSE_ROAMING_NOT_ALLOWED_IN_THIS_TRACKING_AREA:
        return "Roaming not allowed in this tracking area";
    case OGS_5GMM_CAUSE_NO_SUITABLE_CELLS_IN_TRACKING_AREA:
        return "No suitable cells in tracking area";
    case OGS_5GMM_CAUSE_MAC_FAILURE:
        return "MAC failure";
    case OGS_5GMM_CAUSE_SYNCH_FAILURE:
        return "Synch failure";
    case OGS_5GMM_CAUSE_CONGESTION:
        return "Congestion";
    case OGS_5GMM_CAUSE_UE_SECURITY_CAPABILITIES_MISMATCH:
        return "UE security capabilities mismatch";
    case OGS_5GMM_CAUSE_SECURITY_MODE_REJECTED_UNSPECIFIED:
        return "Security mode rejected unspecified";
    case OGS_5GMM_CAUSE_NON_5G_AUTHENTICATION_UNACCEPTABLE:
        return "Non-5G authentication unacceptable";
    case OGS_5GMM_CAUSE_N1_MODE_NOT_ALLOWED:
        return "N1 mode not allowed";
    case OGS_5GMM_CAUSE_RESTRICTED_SERVICE_AREA:
        return "Restricted service area";
    case OGS_5GMM_CAUSE_REDIRECTION_TO_EPC_REQUIRED:
        return "Redirection to EPC required";
    case 36:
        return "IAB-node operation not authorized";
    case OGS_5GMM_CAUSE_LADN_NOT_AVAILABLE:
        return "LADN not available";
    case OGS_5GMM_CAUSE_NO_NETWORK_SLICES_AVAILABLE:
        return "No network slices available";
    case OGS_5GMM_CAUSE_MAXIMUM_NUMBER_OF_PDU_SESSIONS_REACHED:
        return "Maximum number of PDU sessions reached";
    case OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE_AND_DNN:
        return "Insufficient resources for specific slice and DNN";
    case OGS_5GMM_CAUSE_INSUFFICIENT_RESOURCES_FOR_SPECIFIC_SLICE:
        return "Insufficient resources for specific slice";
    case OGS_5GMM_CAUSE_NGKSI_ALREADY_IN_USE:
        return "ngKSI already in use";
    case OGS_5GMM_CAUSE_NON_3GPP_ACCESS_TO_5GCN_NOT_ALLOWED:
        return "Non-3GPP access to 5GCN not allowed";
    case OGS_5GMM_CAUSE_SERVING_NETWORK_NOT_AUTHORIZED:
        return "Serving network not authorized";
    case OGS_5GMM_CAUSE_TEMPORARILY_NOT_AUTHORIZED_FOR_THIS_SNPN:
        return "Temporarily not authorized for this SNPN";
    case OGS_5GMM_CAUSE_PERMANENTLY_NOT_AUTHORIZED_FOR_THIS_SNPN:
        return "Permanently not authorized for this SNPN";
    case OGS_5GMM_CAUSE_NOT_AUTHORIZED_FOR_THIS_CAG_OR_AUITHORIZED_FOR_CAG_CELLS_ONLY:
        return "Not authorized for this CAG or authorized for CAG cells only";
    case 77:
        return "Wireline access area not allowed";
    case 78:
        return "PLMN not allowed to operate at the present UE location";
    case 79:
        return "UAS services not allowed";
    case 80:
        return "Disaster roaming for the determined PLMN with disaster condition not allowed";
    case 81:
        return "Selected N3IWF is not compatible with the allowed NSSAI";
    case 82:
        return "Selected TNGF is not compatible with the allowed NSSAI";
    case OGS_5GMM_CAUSE_PAYLOAD_WAS_NOT_FORWARDED:
        return "Payload was not forwarded";
    case OGS_5GMM_CAUSE_DNN_NOT_SUPPORTED_OR_NOT_SUBSCRIBED_IN_THE_SLICE:
        return "DNN not supported or not subscribed in the slice";
    case OGS_5GMM_CAUSE_INSUFFICIENT_USER_PLANE_RESOURCES_FOR_THE_PDU_SESSION:
        return "Insufficient user-plane resources for the PDU session";
    case 93:
        return "Onboarding services terminated";
    case 94:
        return "User plane positioning not authorized";
    case OGS_5GMM_CAUSE_SEMANTICALLY_INCORRECT_MESSAGE:
        return "Semantically incorrect message";
    case OGS_5GMM_CAUSE_INVALID_MANDATORY_INFORMATION:
        return "Invalid mandatory information";
    case OGS_5GMM_CAUSE_MESSAGE_TYPE_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "Message type non-existent or not implemented";
    case OGS_5GMM_CAUSE_MESSAGE_TYPE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE:
        return "Message type not compatible with the protocol state";
    case OGS_5GMM_CAUSE_INFORMATION_ELEMENT_NON_EXISTENT_OR_NOT_IMPLEMENTED:
        return "Information element non-existent or not implemented";
    case OGS_5GMM_CAUSE_CONDITIONAL_IE_ERROR:
        return "Conditional IE error";
    case OGS_5GMM_CAUSE_MESSAGE_NOT_COMPATIBLE_WITH_THE_PROTOCOL_STATE:
        return "Message not compatible with the protocol state";
    case OGS_5GMM_CAUSE_PROTOCOL_ERROR_UNSPECIFIED:
        return "Protocol error unspecified";
    default:
        return "Unassigned or future 5GMM cause";
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

static int imsi_from_null_scheme_suci(
        const char *suci, char *imsi, size_t imsi_size)
{
    char copy[256];
    char *field[8];
    char *token = NULL;
    char *saveptr = NULL;
    int count = 0;
    int length;

    if (!suci || strlen(suci) >= sizeof(copy))
        return OGS_ERROR;

    strcpy(copy, suci);
    token = strtok_r(copy, "-", &saveptr);
    while (token && count < (int)(sizeof(field) / sizeof(field[0]))) {
        field[count++] = token;
        token = strtok_r(NULL, "-", &saveptr);
    }

    if (token || count != 8 ||
        strcmp(field[0], "suci") || strcmp(field[1], "0") ||
        strcmp(field[5], "0") ||
        !digits_only(field[2]) || !digits_only(field[3]) ||
        !digits_only(field[7]) ||
        strlen(field[2]) != 3 ||
        (strlen(field[3]) != 2 && strlen(field[3]) != 3)) {
        return OGS_ERROR;
    }

    length = snprintf(imsi, imsi_size, "%s%s%s",
            field[2], field[3], field[7]);
    if (length < 0 || (size_t)length >= imsi_size ||
        !digits_only(imsi) || strlen(imsi) > OGS_MAX_IMSI_BCD_LEN) {
        return OGS_ERROR;
    }

    return OGS_OK;
}

static int copy_previous_rows(FILE *source, int destination)
{
    char line[768];

    if (!source)
        return OGS_OK;

    if (fgets(line, sizeof(line), source) &&
        strcmp(line, REGISTRATION_REJECT_CSV_HEADER) &&
        write_all(destination, line, strlen(line)) != OGS_OK) {
        return OGS_ERROR;
    }

    while (fgets(line, sizeof(line), source)) {
        if (write_all(destination, line, strlen(line)) != OGS_OK)
            return OGS_ERROR;
    }

    if (ferror(source)) {
        errno = EIO;
        return OGS_ERROR;
    }

    return OGS_OK;
}

int amf_registration_reject_audit_append(
        const amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause)
{
    const char *path = getenv("AMF_UNAUTHORIZED_REGISTRATION_CSV");
    const char *imei = "unknown";
    const char *imsi = "unknown";
    const char *identity = "unknown";
    const char *reason = gmm_cause_name(gmm_cause);
    char imei_bcd[OGS_MAX_IMSI_BCD_LEN+1] = "";
    char imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1] = "";
    char temp_path[OGS_MAX_FILEPATH_LEN];
    char row[768];
    struct timeval tv;
    struct tm local;
    FILE *source = NULL;
    int destination = -1;
    int path_length, row_length, rv = OGS_ERROR;

    ogs_assert(amf_ue);

    if (!path || !*path)
        path = DEFAULT_REGISTRATION_REJECT_CSV;

    if (amf_ue->supi && *amf_ue->supi) {
        identity = amf_ue->supi;
        if (!strncmp(amf_ue->supi, "imsi-", 5) &&
            digits_only(amf_ue->supi + 5) &&
            strlen(amf_ue->supi + 5) <= OGS_MAX_IMSI_BCD_LEN) {
            imsi = amf_ue->supi + 5;
        }
    } else if (amf_ue->suci && *amf_ue->suci) {
        identity = amf_ue->suci;
        if (imsi_from_null_scheme_suci(
                    amf_ue->suci, imsi_bcd, sizeof(imsi_bcd)) == OGS_OK)
            imsi = imsi_bcd;
    }

    if (imei_from_imeisv(
                amf_ue->imeisv_bcd, imei_bcd, sizeof(imei_bcd)) == OGS_OK)
        imei = imei_bcd;

    ogs_gettimeofday(&tv);
    ogs_localtime(tv.tv_sec, &local);

    row_length = snprintf(row, sizeof(row),
            "%04d-%02d-%02d,%02d:%02d:%02d,%s,%s,%s,%u,%s\n",
            local.tm_year + 1900, local.tm_mon + 1, local.tm_mday,
            local.tm_hour, local.tm_min, local.tm_sec,
            imei, imsi, identity, (unsigned int)gmm_cause, reason);
    if (row_length < 0 || (size_t)row_length >= sizeof(row)) {
        ogs_error("Cannot format registration reject CSV row");
        return OGS_ERROR;
    }

    path_length = snprintf(
            temp_path, sizeof(temp_path), "%s.tmp.XXXXXX", path);
    if (path_length < 0 || (size_t)path_length >= sizeof(temp_path)) {
        ogs_error("Registration reject CSV path is too long [%s]", path);
        return OGS_ERROR;
    }

    source = fopen(path, "r");
    if (!source && errno != ENOENT) {
        ogs_error("Cannot read registration reject CSV [%s]: %s",
                path, strerror(errno));
        return OGS_ERROR;
    }

    destination = mkstemp(temp_path);
    if (destination < 0) {
        ogs_error("Cannot create registration reject CSV temporary file "
                "[%s]: %s", temp_path, strerror(errno));
        if (source)
            fclose(source);
        return OGS_ERROR;
    }
    if (fchmod(destination, 0644) != 0) {
        ogs_error("Cannot set registration reject CSV permissions [%s]: %s",
                temp_path, strerror(errno));
        close(destination);
        if (source)
            fclose(source);
        unlink(temp_path);
        return OGS_ERROR;
    }

    if (write_all(destination,
                REGISTRATION_REJECT_CSV_HEADER,
                sizeof(REGISTRATION_REJECT_CSV_HEADER) - 1) != OGS_OK ||
        write_all(destination, row, row_length) != OGS_OK ||
        copy_previous_rows(source, destination) != OGS_OK ||
        fsync(destination) != 0) {
        ogs_error("Cannot update registration reject CSV [%s]: %s",
                path, strerror(errno));
        goto cleanup;
    }

    if (source && fclose(source) != 0) {
        source = NULL;
        ogs_error("Cannot close registration reject CSV [%s]: %s",
                path, strerror(errno));
        goto cleanup;
    }
    source = NULL;

    if (close(destination) != 0) {
        destination = -1;
        ogs_error("Cannot close registration reject CSV temporary file "
                "[%s]: %s", temp_path, strerror(errno));
        goto cleanup;
    }
    destination = -1;

    if (rename(temp_path, path) != 0) {
        ogs_error("Cannot replace registration reject CSV [%s]: %s",
                path, strerror(errno));
        goto cleanup;
    }

    ogs_warn("Registration reject recorded: IMSI[%s] IMEI[%s] "
            "Identity[%s] Cause[%u:%s] CSV[%s]",
            imsi, imei, identity, (unsigned int)gmm_cause, reason, path);
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
