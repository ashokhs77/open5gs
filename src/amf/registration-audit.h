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

#ifndef AMF_REGISTRATION_AUDIT_H
#define AMF_REGISTRATION_AUDIT_H

#include "context.h"

#ifdef __cplusplus
extern "C" {
#endif

int amf_registration_reject_audit_append(
        const amf_ue_t *amf_ue, ogs_nas_5gmm_cause_t gmm_cause);

#ifdef __cplusplus
}
#endif

#endif /* AMF_REGISTRATION_AUDIT_H */
