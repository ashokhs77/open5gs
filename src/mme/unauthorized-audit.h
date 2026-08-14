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

#ifndef MME_UNAUTHORIZED_AUDIT_H
#define MME_UNAUTHORIZED_AUDIT_H

#include "mme-context.h"

#ifdef __cplusplus
extern "C" {
#endif

int mme_unauthorized_audit_init(void);
int mme_unauthorized_audit_append(
        const mme_ue_t *mme_ue, const char *reject_message,
        int emm_cause, const char *reason_override);

#ifdef __cplusplus
}
#endif

#endif /* MME_UNAUTHORIZED_AUDIT_H */
